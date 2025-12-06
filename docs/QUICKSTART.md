# BreachScope 빠른 시작 가이드

## 🚀 가장 간단한 실행 방법

### 방법 1: 간편 스크립트 사용 (가장 간단!)

#### Windows
```cmd
run.bat
```

또는
```cmd
python run.py
```

#### Linux/Mac
```bash
chmod +x run.sh
./run.sh
```

또는
```bash
python3 run.py
```

**기본 동작**: 데모 모드로 실행 (샘플 로그 자동 생성)

### 방법 2: 직접 실행 (이제 더 간단해졌습니다!)

#### 데모 실행 (가장 간단)
```bash
python -m breachscope.cli --demo
```

**기본값 자동 적용**: `--rules rules`, `--out out/report` 자동 설정

#### 실제 로그 분석
```bash
python -m breachscope.cli --input logs
```

**기본값 자동 적용**: `--rules rules`, `--out out/report` 자동 설정

## 📝 간편 스크립트 옵션

`run.py` 스크립트는 기본값을 자동으로 설정합니다:

- `--rules rules` (자동 추가)
- `--out out/report` (자동 추가)

따라서 다음과 같이 간단하게 실행 가능:

```bash
# 데모 실행
python run.py --demo

# 실제 로그 분석
python run.py --input logs

# 옵션 추가
python run.py --input logs --min-severity high --export-json
```

## 🎯 자주 사용하는 명령어

### 1. 데모 실행 (테스트)
```bash
python run.py --demo
```

### 2. 실제 로그 분석
```bash
python run.py --input <로그폴더>
```

### 3. JSON/CSV도 함께 생성
```bash
python run.py --input logs --export-json --export-csv
```

### 4. 브라우저에서 자동 열기
```bash
python run.py --demo --open
```

### 5. 필터 적용
```bash
python run.py --input logs --min-severity high --mitre-include T1059.001
```

## 🌐 웹 UI (가장 편리)

```bash
# Windows
run_web_fastapi.bat

# Linux/Mac
./run_web_fastapi.sh
```

또는 직접 실행:
```bash
python -m uvicorn web.app_fastapi:app --host 0.0.0.0 --port 8501
```

브라우저에서 `http://localhost:8501`로 접속하여 파일 업로드 → 분석 → 리포트 다운로드

## ⚙️ 설정 파일로 더 편하게

프로젝트 루트에 `breachscope.yaml` 생성:

```yaml
rules: rules
out: out/report
export_json: true
export_csv: true
min_severity: medium
```

그러면 명령어가 더 간단해집니다:
```bash
python run.py --input logs
```

## 💡 팁

1. **가장 빠른 테스트**: `python run.py --demo`
2. **웹 UI가 가장 편함**: `run_web_fastapi.bat` (Windows) 또는 `./run_web_fastapi.sh` (Linux/Mac)
3. **자주 쓰는 옵션은 설정 파일에**: `breachscope.yaml`
