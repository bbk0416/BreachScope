@echo off
REM BreachScope 웹 UI 실행 스크립트 (래퍼)
python -m uvicorn web.app_fastapi:app --host 0.0.0.0 --port 8501 --reload
