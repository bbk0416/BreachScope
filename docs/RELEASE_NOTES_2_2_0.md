# BreachScope v2.2.0

v2.1.2 이후의 기능·운영 검증을 묶은 minor release입니다.

## 주요 변경

- 현재 detector를 73 rules / 49 ATT&CK techniques로 확장하고 P2-36C fresh current-rulepack revalidation을 완료했습니다.
- organization-scoped retained case, audit, object-storage namespace, rule lifecycle 및 API-key delegation을 추가했습니다.
- OIDC SSO와 SCIM 2.0 Users/Groups/Bulk/nested-group provisioning을 추가했습니다.
- SCIM identity store에 SQLite/PostgreSQL backend와 migration tooling을 추가했습니다.
- 실제 PostgreSQL 16.15 + psycopg 3.3.5 E2E에서 schema, shared state, transaction rollback, advisory-lock serialization, SQLite→PostgreSQL migration을 확인했습니다.
- encrypted S3-compatible remote case archive, remote-only read/re-analysis, replica verification API를 추가했습니다.
- clean wheel install을 Windows/Linux/macOS에서 검증하고, installed-wheel readiness/self-test가 packaged rules/templates를 사용하도록 수정했습니다.
- GitHub Actions CI를 실제로 통과하도록 historical evidence fetch, shell-safe env generation, pinned Python 3.11 workflow conditions를 수정했습니다.
- object-storage, artifact-encryption, SCIM migration의 rollback 실패 경로를 별도 회귀 테스트로 고정했습니다.

## 검증 상태

- release PR #355 / CI run #515: Linux Python 3.10 / 3.11 / 3.12, Windows Python 3.11, Windows EVTX smoke, Linux go-live PASS
- Docker Build run #515: build + container smoke PASS
- 최종 `2.2.0` wheel clean install: Windows 로컬 / Ubuntu GitHub-hosted / macOS Intel GitHub-hosted PASS
- project readiness: 100/100
- quality gate: 100/100
- current detection evidence verifier: PASS
- real PostgreSQL single-host E2E: PASS

## 탐지 evidence 경계

현재 73-rule detector의 fresh revalidation은 P2-36C입니다.

- attack fixtures: 2
- HIT: 1
- MISS: 1
- source-intent benign parsed events: 112,411
- benign flagged events: 1
- benign parse errors: 0

이 수치의 해석 경계는 다음과 같습니다.

- 1/2 fixture hit fraction은 event-level recall이 아닙니다.
- 1/112,411 source-intent benign flagged-event fraction은 confirmed 또는 production false-positive rate가 아닙니다.
- production accuracy / precision / recall / false-positive rate는 계속 NOT_CLAIMED입니다.
- P2-14E, P2-35M 등 이전 rulepack evidence는 역사 기록으로 보존합니다.

## 운영 claim 경계

이번 릴리스가 실제로 확인한 범위 밖의 항목은 그대로 남깁니다.

- multi-host PostgreSQL HA: NOT_TESTED
- managed-cloud PostgreSQL: NOT_TESTED
- cross-machine BreachScope replica behavior: NOT_TESTED
- production-scale load/capacity: NOT_TESTED
- PostgreSQL backup/restore and credential rotation: NOT_TESTED
- production detection accuracy/recall/FPR: NOT_CLAIMED
