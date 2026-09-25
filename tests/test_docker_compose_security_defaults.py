from pathlib import Path


def test_compose_defaults_to_loopback_and_configurable_host_port():
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
    env_example = (root / ".env.example").read_text(encoding="utf-8")

    assert "${BS_BIND_ADDRESS:-127.0.0.1}:${BS_HOST_PORT:-8000}:8000" in compose
    assert "BS_BIND_ADDRESS=127.0.0.1" in env_example
    assert "BS_HOST_PORT=8000" in env_example


def test_docker_runtime_image_marks_repository_checks_not_applicable():
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert "BS_RUNTIME_IMAGE=1" in dockerfile
