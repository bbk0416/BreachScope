import subprocess
import sys
import zipfile
from pathlib import Path


def test_built_wheel_contains_runtime_assets(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
        ],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr

    wheels = list(wheel_dir.glob("breachscope-*.whl"))
    assert len(wheels) == 1

    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())

    assert "breachscope/runtime_data/templates/report.html.j2" in names
    assert "breachscope/runtime_data/templates/web_index.html" in names
    assert "breachscope/runtime_data/rules/p2_11_calibration_rules.yml" in names
    assert "breachscope/runtime_data/rules/README.txt" in names
