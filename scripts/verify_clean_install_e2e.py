#!/usr/bin/env python3
"""Verify a clean BreachScope wheel install outside the source checkout."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _python_command() -> list[str]:
    version_file = ROOT / ".python-version"
    requested = (
        version_file.read_text(encoding="utf-8").strip()
        if version_file.is_file()
        else ""
    )
    major_minor = ".".join(requested.split(".")[:2]) if requested else ""

    if os.name == "nt" and shutil.which("py") and major_minor:
        return ["py", f"-{major_minor}"]

    if major_minor:
        candidate = shutil.which(f"python{major_minor}")
        if candidate:
            return [candidate]

    return [sys.executable]


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd or ROOT),
        env=env,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _persist(result: dict[str, object], path: Path | None) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2),
        encoding="utf-8",
    )


def _wait_for_health(port: int) -> dict[str, object]:
    last_error: Exception | None = None
    for _ in range(60):
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/health",
                timeout=2,
            ) as response:
                health = json.loads(response.read().decode("utf-8"))
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/health/ready",
                timeout=2,
            ) as response:
                ready = json.loads(response.read().decode("utf-8"))
            return {
                "health_code": 200,
                "health": health,
                "ready_code": 200,
                "ready": ready,
            }
        except Exception as exc:  # pragma: no cover - integration polling
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"uvicorn health probe failed: {last_error}")


def verify(*, result_path: Path | None = None) -> dict[str, object]:
    work = Path(tempfile.mkdtemp(prefix="breachscope-clean-install-e2e-"))
    dist = work / "dist"
    venv = work / "venv"
    run_dir = work / "run"
    dist.mkdir()
    run_dir.mkdir()

    base_python = _python_command()
    result: dict[str, object] = {
        "status": "started",
        "base_python_command": base_python,
        "source_checkout_used_at_runtime": False,
        "cleanup": False,
    }
    _persist(result, result_path)

    try:
        version = _run(
            [*base_python, "-c", "import platform; print(platform.python_version())"],
            timeout=60,
        ).stdout.strip()
        result["python_version"] = version
        _persist(result, result_path)

        _run(
            [
                *base_python,
                "-m",
                "pip",
                "wheel",
                ".",
                "--no-deps",
                "--wheel-dir",
                str(dist),
            ],
            timeout=300,
        )
        wheels = sorted(dist.glob("breachscope-*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"Expected one BreachScope wheel, found: {wheels}")
        wheel = wheels[0]
        result["wheel_name"] = wheel.name
        result["wheel_build"] = "PASS"
        _persist(result, result_path)

        _run([*base_python, "-m", "venv", str(venv)], timeout=180)
        py = _venv_python(venv)
        if not py.exists():
            raise RuntimeError(f"Fresh venv Python is missing: {py}")
        result["fresh_venv"] = "PASS"
        _persist(result, result_path)

        _run(
            [
                str(py),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                str(wheel),
            ],
            cwd=run_dir,
            timeout=600,
        )
        result["wheel_install_with_dependencies"] = "PASS"
        _persist(result, result_path)

        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        state = run_dir / "state"
        env["BS_CASES_ROOT"] = str(state / "cases")
        env["BS_AUDIT_LOG_PATH"] = str(state / "audit.jsonl")
        env["BS_BACKUP_ROOT"] = str(state / "backups")
        env["BS_RULE_TUNING_PATH"] = str(state / "rule_tuning.json")
        env["BS_RULE_AUTHORING_ROOT"] = str(state / "rule_authoring")
        env["BS_RULE_ACTIVATION_PATH"] = str(state / "rule_activation.json")

        probe = _run(
            [
                str(py),
                "-c",
                (
                    "import json, pathlib; "
                    "from importlib.metadata import version; "
                    "import breachscope, api.main; "
                    "from breachscope.runtime_paths import "
                    "default_rules_dir, default_templates_dir; "
                    "r=default_rules_dir(); t=default_templates_dir(); "
                    "print(json.dumps({"
                    "'version':version('breachscope'),"
                    "'breachscope_file':breachscope.__file__,"
                    "'api_file':api.main.__file__,"
                    "'rules':str(r),'templates':str(t),"
                    "'rule_files':len(list(pathlib.Path(r).glob('*.y*ml'))),"
                    "'report_template_exists':"
                    "(pathlib.Path(t)/'report.html.j2').is_file(),"
                    "'web_template_exists':"
                    "(pathlib.Path(t)/'web_index.html').is_file()"
                    "}))"
                ),
            ],
            cwd=run_dir,
            env=env,
            timeout=120,
        )
        probe_data = json.loads(probe.stdout.strip().splitlines()[-1])
        if "site-packages" not in probe_data["breachscope_file"].lower():
            raise RuntimeError("breachscope imported outside fresh site-packages")
        if "site-packages" not in probe_data["api_file"].lower():
            raise RuntimeError("api imported outside fresh site-packages")
        if probe_data["rule_files"] < 5:
            raise RuntimeError("packaged rule files are incomplete")
        if not probe_data["report_template_exists"]:
            raise RuntimeError("packaged report template is missing")
        if not probe_data["web_template_exists"]:
            raise RuntimeError("packaged web template is missing")

        result["installed_imports"] = "PASS"
        result["installed_version"] = probe_data["version"]
        result["packaged_rule_files"] = probe_data["rule_files"]
        result["packaged_templates"] = "PASS"
        result["source_checkout_used_at_runtime"] = False
        _persist(result, result_path)

        demo = _run(
            [str(py), "-m", "breachscope.cli", "--demo"],
            cwd=run_dir,
            env=env,
            timeout=180,
        )
        result["demo_cli_exit"] = 0
        result["demo_cli_stdout_tail"] = demo.stdout.strip().splitlines()[-5:]
        _persist(result, result_path)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])

        server = subprocess.Popen(
            [
                str(py),
                "-m",
                "uvicorn",
                "api.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=str(run_dir),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            health = _wait_for_health(port)
            if health["health_code"] != 200:
                raise RuntimeError("health endpoint did not return HTTP 200")
            if health["health"]["status"] != "healthy":
                raise RuntimeError("health endpoint is not healthy")
            if health["ready_code"] != 200:
                raise RuntimeError("readiness endpoint did not return HTTP 200")
            if health["ready"]["status"] != "ready":
                raise RuntimeError("readiness endpoint is not ready")
            result["fastapi_health"] = "PASS"
            result["fastapi_readiness"] = "PASS"
            _persist(result, result_path)
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)

        result["status"] = "PASS"
        _persist(result, result_path)
    except Exception as exc:
        result["status"] = "FAIL"
        result["error"] = f"{type(exc).__name__}: {exc}"
        _persist(result, result_path)
        raise
    finally:
        try:
            shutil.rmtree(work)
            result["cleanup"] = not work.exists()
        except Exception as exc:  # pragma: no cover - cleanup path
            result["cleanup"] = False
            result["cleanup_error"] = f"{type(exc).__name__}: {exc}"
        _persist(result, result_path)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build the current source as a wheel, install it into a fresh "
            "venv outside the checkout, and smoke-test CLI and FastAPI."
        )
    )
    parser.add_argument(
        "--result",
        default="",
        help="Optional JSON path for persistent step-by-step results.",
    )
    args = parser.parse_args()
    result_path = Path(args.result).expanduser().resolve() if args.result else None

    try:
        result = verify(result_path=result_path)
    except Exception as exc:
        print(
            json.dumps(
                {"status": "FAIL", "error": f"{type(exc).__name__}: {exc}"},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if (
        result.get("status") == "PASS"
        and result.get("cleanup") is True
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())
