"""
FastAPI 의존성 주입
"""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# 템플릿 환경 설정
templates_dir = Path(__file__).parent.parent / "templates"
jinja_env = Environment(loader=FileSystemLoader(str(templates_dir)))

def get_templates_env() -> Environment:
    """템플릿 환경 반환"""
    return jinja_env

def render_template(template_name: str, **kwargs) -> str:
    """템플릿 렌더링 헬퍼"""
    template = jinja_env.get_template(template_name)
    return template.render(**kwargs)
