BreachScope 규칙 안내 (안전 예시)

1) 네이티브 스키마
- 필수: id, name, pattern
- 선택: description, field, fields, operator, severity, mitre_technique

필드 설명
- id: 규칙 고유 ID
- name: 규칙 이름
- description: 설명(선택)
- field: 기본 검사 필드(기본값: command_line)
- fields: 다중 필드 검사 시 사용 (문자열 콤마 또는 문자열 리스트)
- operator: 매칭 연산자 (regex|contains|startswith|endswith|equals)
  · operator가 없으면 pattern이 정규식으로 해석됨
  · contains 등 문자열 매칭은 대소문자 무시
- pattern: 매칭 패턴 (연산자에 따라 의미 달라짐)
- severity: low|medium|high|critical (기본 medium)
- mitre_technique: 예) T1059.001 (선택)

예시
- id: R-ENC
  name: Encoded PowerShell Command
  field: command_line
  operator: contains
  pattern: "-encodedcommand|-enc"
  severity: medium

2) Sigma-like 최소 지원 (간이 변환)
- title, id(선택), tags(선택: attack.tXXXX), detection.selection.CommandLine|contains
- condition: selection 형태만 지원
  예: rules/sigma_example.yml 참고

주의 (AV/EDR)
- 저장소에는 공격 도구명/긴 Base64 본문을 평문으로 보관하지 마세요.
- 리포트는 기본적으로 위험 토큰과 긴 Base64를 마스킹합니다(해제: --no-redact).
