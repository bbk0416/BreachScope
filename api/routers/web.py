"""
웹 UI 라우터
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from api.dependencies import render_template

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index():
    """메인 페이지"""
    html = render_template("web_index.html")
    return HTMLResponse(content=html)
