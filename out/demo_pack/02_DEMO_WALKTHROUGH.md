# 5-Minute Demo Walkthrough

## 0:00–0:40 Problem framing

중소 조직은 사고가 의심돼도 Windows 로그를 수동으로 뒤져야 해서 초동 대응이 늦어집니다. BreachScope는 로그를 올리면 탐지, ATT&CK 매핑, IOC 후보, 케이스 패키지, 한글 보고서를 자동 생성합니다.

## 0:40–1:30 Run the built-in scenario

```bash
python scripts/run.py --demo-scenario all --out out/demo/report --export-json --export-csv --pdf
```

## 1:30–2:40 Show the dashboard/report

이번 데모는 합성 이벤트 **48개**에서 탐지 **53건**, 리스크 **100/100 (critical)**를 생성합니다.

강조할 화면:

- Risk Score / Executive Summary
- Top Findings
- Incident Timeline
- ATT&CK tactic coverage
- IOC CSV / case ZIP download
- Korean PDF report

## 2:40–3:40 Explain the sample scenarios

| Scenario | Events | Expected ATT&CK |
|---|---|---|
| powershell_downloader | 4 | T1059.001, T1105 |
| credential_dump_triage | 5 | T1003.001, T1003.002, T1003.003 |
| ransomware_preparation | 5 | T1490, T1562.001, T1070.001 |
| lateral_movement_remote_admin | 4 | T1021.006, T1569.002, T1543.003, T1047 |
| active_directory_discovery | 7 | T1087.001, T1087.002, T1482, T1135, T1057, T1518.001 |
| lolbin_proxy_execution | 7 | T1218.005, T1218.011, T1218.010, T1218.003, T1127.001, T1218.004, T1202 |
| cloud_exfiltration_staging | 4 | T1560.001, T1567.002 |
| persistence_mechanisms | 4 | T1547.001, T1053.005, T1543.003 |
| defense_evasion_controls | 4 | T1562.001, T1562.002, T1562.004 |
| user_data_collection | 4 | T1555.003, T1115, T1113, T1560.001 |

## 3:40–4:30 Explain operational features

- 관리자 로그인/HttpOnly 세션과 API Key 병행 지원
- 케이스 이력, 담당자/상태/메모/종결 요약 관리
- 감사 로그 JSONL/CSV export와 무결성 해시
- 백업, 케이스 보존정리, 헬스체크, 메트릭, 셀프테스트
- CI/CD, Docker smoke test, 릴리즈 checksum/manifest

## 4:30–5:00 Close

단순 로그 검색기가 아니라, 내부 보안팀/컨설턴트가 사고 초동분석 결과를 관리하고 납품물로 내보내는 DFIR 운영 콘솔이라는 점을 강조합니다.
