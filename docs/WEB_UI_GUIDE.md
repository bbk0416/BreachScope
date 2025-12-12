# BreachScope 웹 UI 가이드

## 🚀 FastAPI 웹 UI

### 실행 방법

#### Windows
```cmd
run_web_fastapi.bat
```

#### Linux/Mac
```bash
chmod +x run_web_fastapi.sh
./run_web_fastapi.sh
```

#### 직접 실행
```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8501 --reload
```

### 접속
브라우저에서 `http://localhost:8501` 접속

### 기능
- ✅ 파일 업로드 (드래그 앤 드롭)
- ✅ 옵션 설정 (GUI)
- ✅ 분석 실행
- ✅ 리포트 다운로드 (HTML, JSON, CSV, PDF)
- ✅ REST API 제공 (`/api/analyze`, `/api/rules`)
- ✅ 자동 문서화 (`/docs`)

### API 문서
- Swagger UI: `http://localhost:8501/docs`
- ReDoc: `http://localhost:8501/redoc`

## 💡 FastAPI의 특징 및 장점

1. **REST API 제공**: 다른 애플리케이션에서도 사용 가능
2. **자동 문서화**: `/docs`에서 API 테스트 가능
3. **빠른 성능**: 비동기 처리 지원
4. **유연한 커스터마이징**: HTML/CSS/JS 자유롭게 수정 가능
5. **프로덕션 배포**: Docker, Kubernetes 등에 배포 용이

## 📝 사용 예시

### 웹 UI 사용
1. 브라우저에서 `http://localhost:8501` 접속
2. 로그 파일 업로드
3. 옵션 설정
4. "분석 실행" 클릭
5. 리포트 다운로드

### API 사용 (프로그래밍 방식)
```python
import requests

# 파일 업로드 및 분석
files = {'files': open('logs/events.jsonl', 'rb')}
data = {
    'min_severity': 'medium',
    'use_repo_rules': True,
}

response = requests.post('http://localhost:8501/api/analyze', files=files, data=data)
result = response.json()

# 리포트 다운로드
report_url = f"http://localhost:8501/api/report/{result['work_dir']}?file_type=html"
```

## 🔧 설치

### 필수 패키지
```bash
pip install fastapi uvicorn[standard] python-multipart
```

### 전체 설치
```bash
pip install -r requirements.txt
```

## 🎯 권장 사항

- FastAPI 웹 UI 사용 (`run_web_fastapi.bat` 또는 `run_web_fastapi.sh`)
- REST API를 통한 자동화 및 통합 가능
