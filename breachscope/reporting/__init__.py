"""
보고서 생성 모듈
"""
# 상위 디렉토리의 reporting.py 모듈에서 함수들을 import
# reporting/ 패키지와 reporting.py 모듈이 공존하는 경우를 처리하기 위해
# importlib를 사용하여 상위 모듈을 직접 로드
import sys
import importlib.util
from pathlib import Path

# 상위 디렉토리의 reporting.py 모듈 로드
_reporting_py_path = Path(__file__).parent.parent / "reporting.py"
if _reporting_py_path.exists():
    spec = importlib.util.spec_from_file_location("breachscope._reporting_py", _reporting_py_path)
    _reporting_py_module = importlib.util.module_from_spec(spec)
    sys.modules["breachscope._reporting_py"] = _reporting_py_module
    spec.loader.exec_module(_reporting_py_module)

    # 함수들을 현재 모듈 네임스페이스로 re-export
    build_summary = _reporting_py_module.build_summary
    render_html = _reporting_py_module.render_html
    maybe_render_pdf = _reporting_py_module.maybe_render_pdf
    export_json = _reporting_py_module.export_json
    export_csv = _reporting_py_module.export_csv
else:
    raise ImportError(f"reporting.py 모듈을 찾을 수 없습니다: {_reporting_py_path}")

from .nlg import NLGTemplate

__all__ = ["NLGTemplate", "build_summary", "render_html", "maybe_render_pdf", "export_json", "export_csv"]
