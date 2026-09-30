# BreachScope 현재 아키텍처

이 문서는 **현재 저장소 구현 기준**으로 BreachScope의 구조를 설명합니다.

이전 버전의 이 파일은 초기 기획 PDF에서 추출한 연구 문서였고, “90% 이상의 정확도”, “인간 전문가 수준의 통찰” 같은 목표 표현이 포함되어 있었습니다. 그런 문구는 현재 실전 성능을 증명하는 결과가 아니므로 이 문서에서는 사용하지 않습니다. 과거 내용이 필요하면 Git history에서 확인할 수 있습니다.

## 1. 프로젝트 범위

BreachScope는 Windows Event Log를 중심으로 다음 흐름을 연결하는 DFIR 분석 도구입니다.

```text
EVTX / JSONL / Windows collection
            ↓
       ingest / parse
            ↓
         normalize
            ↓
 native rule detection
 + optional Hayabusa findings
            ↓
          findings
            ↓
 correlation by time / host / user / session
            ↓
     scenario matching
            ↓
 report / IOC / manifest / case package
            ↓
 case history / audit / backup / web API
```

핵심 차별점은 독립 탐지 엔진의 속도 자체보다 **탐지 결과를 사건 흐름과 케이스/보고서로 연결하는 후단 작업**입니다.

## 2. 입력 계층

### JSONL

기본 분석 입력으로 JSONL을 사용할 수 있습니다.

### EVTX

`python-evtx`를 이용해 EVTX 파일을 읽고 JSONL 분석 흐름으로 변환할 수 있습니다.

### Windows live collection

Windows에서는 `wevtutil.exe`를 호출해 Security, System, Application, PowerShell Operational 등의 이벤트 로그를 수집할 수 있습니다.

이 기능은 Windows 전용입니다. GitHub Actions에는 별도 Windows Python 3.11 lane이 있으며 Windows path semantics, EVTX contract, case-history locking, native EVTX collect/convert smoke, CLI, rulepack을 직접 검증합니다. 이는 CI runner 범위의 검증이며 실제 고객 단말·도메인 환경의 운영 적합성을 의미하지는 않습니다.

### 추가 artifact 모듈

`breachscope/artifacts/`에는 Browser, Prefetch, Registry, USB 관련 모듈이 있습니다.

이 모듈이 존재한다고 해서 BreachScope가 모든 Windows forensic artifact를 완전하게 지원한다는 뜻은 아닙니다. 현재 주 분석 흐름은 Windows Event Log 중심입니다.

## 3. 정규화

입력 이벤트는 BreachScope 내부 Event 형태로 정규화됩니다.

이 단계의 목적은 source별 필드 차이를 줄이고 탐지·상관분석에서 공통 필드를 사용할 수 있게 하는 것입니다.

주요 공통 정보는 다음과 같습니다.

- timestamp
- host
- source/provider
- event ID
- user
- command line
- raw source data

Windows 세션 관련 값은 후단 correlation/scenario scope에서 host/user/session lifecycle과 함께 사용됩니다.

## 4. 탐지 계층

### Native rules

프로젝트 내장 YAML 룰팩을 BreachScope analyzer가 처리합니다.

룰팩 개수나 ATT&CK coverage 수치는 코드와 함께 바뀔 수 있으므로 이 아키텍처 문서에 고정 숫자를 박지 않습니다. 현재 값은 다음 명령으로 확인합니다.

```bash
python scripts/run.py --validate-rules
```

### Hayabusa backend

Hayabusa는 선택적으로 외부 backend로 사용할 수 있습니다.

BreachScope는 Hayabusa의 룰 엔진을 다시 구현하지 않습니다. Hayabusa의 `dfir-timeline` JSONL 결과를 BreachScope Finding으로 변환하고, 이후 correlation/scenario/report 단계에 합칩니다.

이 구조는 Hayabusa와 탐지 속도로 경쟁하기보다는 외부 탐지 결과를 사건 분석 workflow에 연결하기 위한 것입니다.

## 5. 상관분석

Correlation 계층은 Finding과 이벤트를 단순 시간 정렬하는 것보다 더 좁은 evidence scope에서 묶는 것을 목표로 합니다.

현재 주요 경계는 다음과 같습니다.

- 시간
- host
- user
- Windows session identity
- session lifecycle

최근 hardening에서는 TargetLogonId 우선순위, canonical session ID, reused session lifecycle, host/user scope 등의 경계를 강화했습니다.

이 로직이 실제 공격 corpus에서 얼마나 정확하게 공격 흐름을 복원하는지는 외부 evaluation으로 별도 측정해야 합니다.

## 6. 시나리오 계층

Scenario 계층은 rule/chain 결과를 템플릿과 비교해 높은 수준의 사건 흐름을 구성합니다.

기본 템플릿과 사용자 정의 YAML 템플릿을 지원하며 다음 정보를 사용합니다.

- required ATT&CK techniques
- optional ATT&CK techniques
- chain patterns
- evidence scope
- confidence 계산

이 기능은 deterministic rule/template 기반입니다. 통계 모델이나 LLM이 인간 분석가처럼 자유 추론하는 구조로 표현하지 않습니다.

## 7. 리포트와 산출물

분석 결과는 다음 산출물로 내보낼 수 있습니다.

- HTML
- JSON
- CSV
- IOC CSV
- rule catalog CSV
- PDF
- manifest
- ZIP case package

Manifest와 case package는 조사 결과 전달과 재검토를 돕기 위한 산출물입니다.

## 8. 웹/API 계층

FastAPI 서비스는 분석, 케이스, 리포트, 인증, 감사로그, 백업, 운영 상태 기능을 제공합니다.

주요 서비스에는 다음이 포함됩니다.

- AnalysisService
- CaseHistoryService
- audit logging
- backup service
- report preview
- upload policy
- work directory management
- path boundary validation

## 9. 케이스 저장과 무결성

기본 웹 분석 케이스는 관리되는 filesystem work directory와 case-history index를 사용합니다.

Case history에는 다음 보호가 있습니다.

- atomic index write
- corrupt JSON/invalid UTF-8 quarantine
- quarantine 실패 시 fail-closed
- thread/process 간 case-history operation lock
- 삭제 실패 시 history 보존
- 관리 경계 밖 경로 삭제 방지

Case/audit/backup/rule 관리 API에는 organization identity가 전달되고 저장·조회 경로가 organization scope로 분리됩니다. 즉 멀티조직 격리 기능 자체는 구현돼 있습니다. 다만 이 구현을 대규모 엔터프라이즈 멀티테넌트 서비스나 HA case cluster가 검증됐다는 뜻으로 해석하지 않습니다.

## 10. SQLite 모듈

`breachscope/storage.py`에는 SQLite 기반 events/findings/chains/scenarios 저장 구현이 있습니다.

- WAL mode
- indexes
- batch insert
- event hash deduplication

이 모듈이 존재하지만 현재 기본 CLI/Web case lifecycle 전체가 SQLite 중심으로 동작한다고 표현하지 않습니다. 성능 문서에서도 SQLite 구현 존재와 제품 전체 처리량을 같은 의미로 취급하지 않습니다.

## 11. 보안 경계

BreachScope에는 다음 방어 기능이 있습니다.

- API key 및 organization-bound API key
- local admin login/session
- OIDC Authorization Code + PKCE SSO
- SCIM 2.0 Users/Groups/Bulk provisioning
- role/organization 기반 RBAC
- login lockout
- HttpOnly/Secure cookie controls
- organization-scoped audit/case/backup/rule access
- audit log 및 integrity option
- upload limits
- managed path boundary
- retained artifact encryption / release signing 경로
- cleanup / backup controls
- production configuration checks

OIDC/SCIM/RBAC이 구현돼 있다는 사실과 외부 서비스 운영 준비가 끝났다는 주장은 구분합니다. TLS termination, 실제 IdP/SCIM 운영 설정, retention 정책, backup/restore 절차, credential rotation, HA/복구 설계, 조직별 보안 검토는 배포 환경에서 별도로 확인해야 합니다.

## 12. CI/릴리즈

현재 CI는 다음을 수행합니다.

- Linux Python 3.10 / 3.11 / 3.12
- Windows Python 3.11
- Linux/macOS clean wheel install + runtime smoke
- compile check
- pytest
- demo CLI smoke
- Windows native EVTX collect/convert smoke
- rulepack validation
- project readiness check
- quality gate
- go-live check
- showcase/publish-prep build

Docker workflow와 release workflow도 별도로 존재합니다. Public GitHub-hosted CI에서 Linux, Windows, Linux clean-install, macOS clean-install lane을 실제 실행해 통과한 기록이 있으며, 이는 지원 runtime 재현성 근거로 사용합니다. 실제 조직 배포·부하·HA를 검증하는 근거로는 사용하지 않습니다.

## 13. 평가 구조

### Synthetic regression

`scripts/evaluate_detection_corpus.py`는 내장 합성 corpus를 이용해 회귀를 확인합니다.

이 결과는 코드 변경으로 기존 탐지가 깨졌는지 확인하는 데 유용하지만 production precision/recall 근거가 아닙니다.

### External holdout

`scripts/evaluate_external_holdout.py`는 외부 corpus 평가를 위한 도구입니다.

외부 평가에서는 commit/rule/corpus를 고정하고 TP/FP/TN/FN, precision, recall, FPR, scenario hit, 실행 시간, peak memory 등을 기록해야 합니다.

현재 73-rule rulepack에는 fresh attack/benign source revalidation 기록이 있습니다. 다만 attack 쪽은 fixture hit/miss 관찰이고 benign 쪽은 source-intent corpus의 flagged-event 관찰값이며, event-level authoritative ground truth가 아닙니다. 따라서 이를 production precision/recall/FPR이나 “90% 정확도” 같은 제품 수치로 표현하지 않습니다.

## 14. 성능 구조

현재 Pipeline은 일반 실행에서 정규화 이벤트를 메모리 리스트로 구성합니다.

Detection에는 병렬 경로가 있지만 전체 ingest→correlation→scenario→report pipeline이 병렬화된 것은 아닙니다.

따라서 대규모 처리량과 peak memory는 별도 benchmark 결과로 판단해야 합니다. 현재 정책은 [PERFORMANCE.md](PERFORMANCE.md)를 참고하세요.

## 15. 현재 비목표

현재 BreachScope가 목표로 하지 않거나 아직 증거가 부족한 영역입니다.

- Hayabusa/Chainsaw보다 빠른 raw detection engine
- 모든 Windows forensic artifact의 완전한 수집/파싱
- 검증된 enterprise-scale multi-tenant 운영
- multi-host HA/cluster orchestration
- SIEM 규모의 장기 log storage
- 사람 검토 없는 자동 차단/사고 확정
- 외부 독립 평가가 끝난 production accuracy 보장

## 16. 현재 개발 우선순위

Windows-native CI, fresh attack/benign revalidation, 실제 PostgreSQL E2E, Windows/Linux/macOS clean-install 재현성은 이미 확보했습니다. 다음 증거가 우선입니다.

1. 재현 가능한 10k/100k/1m throughput·peak-memory benchmark
2. authoritative event-level label을 가진 더 대표적인 attack/benign 평가 corpus
3. multi-host HA/장애복구, backup/restore, credential rotation의 실제 운영 검증
4. public Release asset을 새 환경에서 내려받아 설치하는 경로와 cache 없는 fresh-machine 검증
5. 위 결과에서 드러난 parser/rule/correlation 문제만 선택적으로 수정

이 순서는 “기능이 많아 보이는 프로젝트”보다 **실제 결과를 설명할 수 있는 프로젝트**로 만들기 위한 것입니다.
