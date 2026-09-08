from __future__ import annotations

import io

from breachscope.cli import _configure_utf8_stdio


def test_cli_reconfigures_strict_cp1252_stream_for_utf8_output():
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")

    _configure_utf8_stdio(stream)

    stream.write("✓ 내장 시나리오 샘플 준비")
    stream.flush()

    assert raw.getvalue().decode("utf-8") == "✓ 내장 시나리오 샘플 준비"
    assert stream.encoding.casefold().replace("-", "") == "utf8"
    stream.detach()


def test_cli_stdio_helper_tolerates_non_reconfigurable_stream():
    class PlainStream:
        pass

    _configure_utf8_stdio(PlainStream())
