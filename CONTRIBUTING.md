# BreachScope 기여 가이드

BreachScope 프로젝트에 기여해주셔서 감사합니다! 이 문서는 프로젝트에 기여하는 방법을 안내합니다.

## 기여 방법

### 1. 이슈 리포트

버그를 발견하거나 기능 개선 아이디어가 있으시면 [GitHub Issues](https://github.com/bbk0416/BreachScope/issues)에 이슈를 생성해주세요.

**이슈 작성 시 포함할 내용**:
- 문제 설명 또는 기능 요청 내용
- 재현 단계 (버그인 경우)
- 예상 동작 vs 실제 동작
- 환경 정보 (OS, Python 버전 등)
- 관련 로그 또는 스크린샷

### 2. 코드 기여

#### 개발 환경 설정

```bash
# 저장소 클론
git clone https://github.com/bbk0416/BreachScope.git
cd BreachScope

# 가상 환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
venv\Scripts\activate  # Windows

# 의존성 설치
pip install -r requirements.txt
```

#### 개발 워크플로우

1. **Fork 및 브랜치 생성**
   ```bash
   # Fork 후 원격 저장소 추가
   git remote add upstream https://github.com/bbk0416/BreachScope.git

   # 새 기능 브랜치 생성
   git checkout -b feature/your-feature-name
   # 또는 버그 수정
   git checkout -b fix/your-bug-fix
   ```

2. **코드 작성**
   - 기존 코드 스타일을 따르세요
   - 타입 힌트를 사용하세요
   - Docstring을 작성하세요
   - 의미 있는 커밋 메시지를 작성하세요

3. **테스트**
   ```bash
   # 기본 테스트 실행
   python -m pytest tests/

   # 데모 실행으로 기능 확인
   python scripts/run.py --demo
   ```

4. **커밋 및 푸시**
   ```bash
   git add .
   git commit -m "feat: Add new feature description"
   git push origin feature/your-feature-name
   ```

5. **Pull Request 생성**
   - GitHub에서 Pull Request를 생성하세요
   - 변경 사항을 명확히 설명하세요
   - 관련 이슈 번호를 참조하세요

## 코딩 스타일

### Python 스타일 가이드

- **PEP 8** 준수
- **타입 힌트** 사용 (가능한 경우)
- **Docstring** 작성 (Google 스타일 권장)
- **함수/변수명**: snake_case
- **클래스명**: PascalCase

### 예시

```python
from typing import List, Optional
from pathlib import Path

def process_events(
    events: List[Event],
    output_dir: Optional[Path] = None
) -> List[Finding]:
    """
    이벤트를 처리하여 탐지 결과를 반환합니다.

    Args:
        events: 처리할 이벤트 목록
        output_dir: 출력 디렉토리 (선택)

    Returns:
        탐지 결과 목록

    Raises:
        ValueError: 이벤트 목록이 비어있는 경우
    """
    if not events:
        raise ValueError("이벤트 목록이 비어있습니다")

    # 처리 로직
    findings = []
    # ...

    return findings
```

## 문서화

- 새로운 기능 추가 시 관련 문서를 업데이트하세요
- `docs/` 디렉토리의 관련 문서 수정
- README.md 업데이트 (필요한 경우)
- CHANGELOG.md에 변경 사항 추가

## 테스트

- 새로운 기능은 테스트 코드를 포함해야 합니다
- 기존 테스트가 실패하지 않도록 주의하세요
- 테스트 커버리지를 유지하세요

## 커밋 메시지 규칙

커밋 메시지는 다음 형식을 따르세요:

```
<type>: <subject>

<body>
```

**Type**:
- `feat`: 새로운 기능
- `fix`: 버그 수정
- `docs`: 문서 변경
- `style`: 코드 포맷팅 (기능 변경 없음)
- `refactor`: 리팩토링
- `test`: 테스트 추가/수정
- `chore`: 빌드/설정 변경

**예시**:
```
feat: Add parallel processing support for rule analysis

- Implement ThreadPoolExecutor for concurrent rule matching
- Add enable_parallel parameter to Pipeline class
- Update documentation with performance benchmarks
```

## Pull Request 가이드

### PR 제목 형식
```
<type>: <간단한 설명>
```

### PR 설명 템플릿
```markdown
## 변경 사항
- 변경 내용 1
- 변경 내용 2

## 관련 이슈
Closes #123

## 테스트
- [ ] 기존 테스트 통과
- [ ] 새 기능 테스트 추가
- [ ] 문서 업데이트

## 체크리스트
- [ ] 코드 스타일 준수
- [ ] 타입 힌트 추가
- [ ] Docstring 작성
- [ ] 테스트 코드 작성
- [ ] 문서 업데이트
```

## 리뷰 프로세스

1. PR 생성 후 자동으로 코드 리뷰가 요청됩니다
2. 리뷰어의 피드백을 반영하여 수정하세요
3. 모든 리뷰가 승인되면 머지됩니다

## 질문이 있으신가요?

- GitHub Issues에 질문을 올려주세요
- 프로젝트 메인테이너에게 직접 연락하실 수 있습니다

---

**감사합니다!** BreachScope 프로젝트에 기여해주셔서 감사합니다. 🎉
