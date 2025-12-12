# 사용자 정의 시나리오 템플릿

이 디렉토리에는 사용자 정의 공격 시나리오 템플릿을 YAML 형식으로 정의할 수 있습니다.

## 템플릿 파일 형식

각 템플릿은 다음 필드를 포함해야 합니다:

```yaml
- template_id: unique_id          # 고유 템플릿 ID
  name: 시나리오 이름              # 시나리오 표시 이름
  description: 시나리오 설명       # 상세 설명
  required_techniques:             # 필수 MITRE ATT&CK 기법 리스트
    - T1059.001
  optional_techniques:             # 선택적 MITRE ATT&CK 기법 리스트
    - T1547.001
  chain_patterns:                  # 체인 패턴 리스트 (선택적)
    - download_exec
  attack_stage: execution          # 공격 단계
```

## 공격 단계 (attack_stage)

다음 중 하나를 사용할 수 있습니다:
- `initial_access`: 초기 접근
- `execution`: 실행
- `persistence`: 영구성
- `privilege_escalation`: 권한 상승
- `defense_evasion`: 방어 회피
- `credential_access`: 자격증명 접근
- `discovery`: 탐색
- `lateral_movement`: 측면 이동
- `collection`: 수집
- `command_and_control`: 명령 및 제어
- `exfiltration`: 유출
- `impact`: 영향

## 체인 패턴 (chain_patterns)

다음 중 하나 이상을 사용할 수 있습니다:
- `download_exec`: 다운로드 → 실행
- `encoded_exec`: 인코딩된 명령 실행
- `network_data`: 네트워크 데이터 전송

## 사용 방법

1. 이 디렉토리에 `.yml` 또는 `.yaml` 파일을 생성합니다.
2. 템플릿을 정의합니다 (예: `example_custom_template.yml` 참조).
3. 파이프라인에서 사용자 정의 템플릿 디렉토리를 지정합니다:

```python
from breachscope.pipeline import Pipeline
from pathlib import Path

pipeline = Pipeline(
    rules_dir=Path("rules"),
    custom_scenario_templates_dir=Path("scenarios"),  # 사용자 정의 템플릿 디렉토리
)
```

## 예제

`example_custom_template.yml` 파일을 참조하여 템플릿 작성 방법을 확인할 수 있습니다.
