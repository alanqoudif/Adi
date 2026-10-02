"""JSON rendering and file writing for reports."""

from __future__ import annotations

from pathlib import Path

from adi.reporting.markdown import render_markdown
from adi.reporting.models import Report


def render_json(report: Report) -> str:
    return report.model_dump_json(indent=2)


def write_reports(report: Report, output_dir: Path, formats: tuple[str, ...] = ("markdown", "json")
                  ) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    if "markdown" in formats:
        path = output_dir / "report.md"
        path.write_text(render_markdown(report))
        written["markdown"] = path
    if "json" in formats:
        path = output_dir / "report.json"
        path.write_text(render_json(report))
        written["json"] = path
    return written
