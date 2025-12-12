"""
기본 헬스 체크 테스트
"""
import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_root():
    """루트 엔드포인트 테스트"""
    response = client.get("/")
    assert response.status_code == 200
    assert "name" in response.json()
    assert response.json()["name"] == "BreachScope"


def test_health_check():
    """헬스 체크 엔드포인트 테스트"""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
