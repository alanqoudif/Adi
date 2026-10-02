from __future__ import annotations

from typer.testing import CliRunner

from adi.cli import app


def test_doctor_includes_product_shell_section(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Product Shell" in result.stdout
    assert "Product session(s) recorded" in result.stdout
