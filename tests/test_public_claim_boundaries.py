from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCH = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
PITCH = (ROOT / "docs" / "PORTFOLIO_PITCH.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_architecture_does_not_describe_completed_ci_as_future_work() -> None:
    assert "Windows CI 보강 대상" not in ARCH
    assert "Windows Python 3.11" in ARCH
    assert "Linux/macOS clean wheel install + runtime smoke" in ARCH


def test_architecture_distinguishes_org_isolation_from_enterprise_scale() -> None:
    assert "- enterprise multi-tenancy" not in ARCH
    assert "멀티조직 격리 기능 자체는 구현돼 있습니다" in ARCH
    assert "검증된 enterprise-scale multi-tenant 운영" in ARCH
    assert "multi-host HA/cluster orchestration" in ARCH


def test_portfolio_pitch_does_not_claim_rbac_or_migration_are_missing() -> None:
    assert "would need additional log parsers, RBAC, database migration strategy" not in PITCH
    assert "role-and-organization RBAC" in PITCH
    assert "SQLite→PostgreSQL identity migration exist" in PITCH
    assert "not proof of enterprise-scale operations" in PITCH


def test_public_docs_preserve_detection_quality_claim_boundary() -> None:
    assert "production precision/recall/FPR" in ARCH
    assert "90% 정확도" in ARCH
    assert "외부 독립 평가로 검증된 production-ready 탐지 제품" in README
    nonclaim = README.split("## 프로젝트가 주장하지 않는 것", 1)[1]
    assert "외부 독립 평가로 검증된 production-ready 탐지 제품" in nonclaim
