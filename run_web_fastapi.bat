@echo off
REM BreachScope 웹 UI 실행 래퍼 (루트)
python -m uvicorn api.main:app --host 0.0.0.0 --port 8501 --reload
