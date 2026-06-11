#!/usr/bin/env python3
"""
BreachScope 간편 실행 스크립트
기본값을 사용하여 더 간단하게 실행할 수 있습니다.
"""
import sys
from pathlib import Path

# 프로젝트 루트를 Python 경로에 추가
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))
from breachscope.cli import main

if __name__ == "__main__":
    # 인자가 없으면 데모 실행
    if len(sys.argv) == 1:
        sys.argv.append("--demo")

    main()
