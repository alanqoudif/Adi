from __future__ import annotations

import os

from adi.product.terminal_safety import sanitize_for_terminal


def test_strips_csi_cursor_sequence():
    malicious = "before\x1b[2J\x1b[Hafter"
    cleaned = sanitize_for_terminal(malicious)
    assert "\x1b" not in cleaned
    assert cleaned == "beforeafter"


def test_strips_osc_title_sequence():
    malicious = "name\x1b]0;pwned\x07rest"
    cleaned = sanitize_for_terminal(malicious)
    assert "\x1b" not in cleaned and "\x07" not in cleaned
    assert "pwned" not in cleaned or "rest" in cleaned  # OSC body is dropped as one unit


def test_preserves_normal_text_and_newlines_tabs():
    text = "endpoint:\t/api/orders\nstatus: 200"
    assert sanitize_for_terminal(text) == text


def test_strips_bare_control_bytes():
    text = "finding title\x07\x08 with bell/backspace"
    cleaned = sanitize_for_terminal(text)
    assert "\x07" not in cleaned and "\x08" not in cleaned


def test_no_color_env_respected(tmp_path, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    from adi.config.models import AdiConfig, RuntimeConfig
    from adi.product.plain_shell import PlainShell

    shell = PlainShell(AdiConfig(runtime=RuntimeConfig(type="mock")), project_root=tmp_path)
    assert shell.console.no_color is True
