"""Human-friendly display IDs (ADI-F-001, ADI-H-003, EV-004, ...) derived
deterministically from creation order, so they are stable across resume and
report regeneration. The CLI accepts either a display ID or the raw DB id."""

from __future__ import annotations


def display_id_map(records, prefix: str) -> dict[str, str]:
    """raw id -> display id, numbered by creation order."""
    ordered = sorted(records, key=lambda r: (r.created_at, r.id))
    return {r.id: f"{prefix}-{i:03d}" for i, r in enumerate(ordered, start=1)}


def resolve_id(records, prefix: str, wanted: str) -> str | None:
    """Accepts a raw id or a display id; returns the raw id (or None)."""
    mapping = display_id_map(records, prefix)
    if wanted in mapping:
        return wanted
    for raw, display in mapping.items():
        if display.lower() == wanted.lower():
            return raw
    return None
