import base64
from typing import Optional


def maybe_base64(s: str) -> Optional[str]:
    t = s.strip()
    # Heuristic length and charset
    if len(t) < 8:
        return None
    try:
        data = base64.b64decode(t, validate=True)
    except Exception:
        return None
    # Try UTF-8 then UTF-16LE (common for PowerShell)
    for enc in ("utf-8", "utf-16le", "utf-16"):
        try:
            dec = data.decode(enc)
            if dec.strip():
                return dec
        except Exception:
            continue
    return None


def rot(s: str, n: int) -> str:
    def rot_char(c: str) -> str:
        if "a" <= c <= "z":
            return chr((ord(c) - 97 + n) % 26 + 97)
        if "A" <= c <= "Z":
            return chr((ord(c) - 65 + n) % 26 + 65)
        return c

    return "".join(rot_char(c) for c in s)


def xor(s: str, key: int) -> str:
    return "".join(chr(ord(c) ^ key) for c in s)

