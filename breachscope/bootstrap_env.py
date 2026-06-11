"""Generate safe first-run environment files for BreachScope."""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

SECRET_KEYS = {
    "BS_API_KEY": 40,
    "BS_ADMIN_PASSWORD": 32,
    "BS_SESSION_SECRET": 48,
    "BS_AUDIT_CHAIN_SECRET": 48,
}


def _token(length: int) -> str:
    return secrets.token_urlsafe(length)[: max(length, 24)]


def generate_env_text(template_path: str | Path = ".env.example", *, production: bool = False, https: bool = False) -> tuple[str, dict[str, Any]]:
    template = Path(template_path)
    text = template.read_text(encoding="utf-8") if template.exists() else ""
    if not text:
        text = "BS_API_KEY=change-me\nBS_ADMIN_PASSWORD=change-me\nBS_SESSION_SECRET=change-me\nBS_AUDIT_CHAIN_SECRET=change-me\n"

    generated = {key: _token(length) for key, length in SECRET_KEYS.items()}
    replacements = dict(generated)
    if production:
        replacements["BS_DEPLOYMENT_MODE"] = "production"
        replacements["BS_DISABLE_DOCS"] = "1"
    if https or production:
        replacements["BS_COOKIE_SECURE"] = "1"

    lines = []
    present = set()
    for line in text.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            lines.append(line)
            continue
        key, _sep, _value = line.partition("=")
        key = key.strip()
        if key in replacements:
            lines.append(f"{key}={replacements[key]}")
            present.add(key)
        else:
            lines.append(line)
    for key, value in replacements.items():
        if key not in present:
            lines.append(f"{key}={value}")
    if production and "BS_DEPLOYMENT_MODE" not in present:
        # already appended above; this branch stays explicit for readability
        pass
    body = "\n".join(lines).rstrip() + "\n"
    summary = {
        "generated_keys": sorted(generated),
        "production": production,
        "https": https or production,
        "template": str(template),
    }
    return body, summary


def write_env_file(output_path: str | Path = ".env", template_path: str | Path = ".env.example", *, production: bool = False, https: bool = False, force: bool = False) -> dict[str, Any]:
    output = Path(output_path)
    if output.exists() and not force:
        raise FileExistsError(f"{output} already exists. Use --force to overwrite.")
    body, summary = generate_env_text(template_path, production=production, https=https)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(body, encoding="utf-8")
    output.chmod(0o600)
    return {**summary, "output": str(output), "mode": oct(output.stat().st_mode & 0o777)}
