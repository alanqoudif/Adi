"""Deterministic nuclei JSONL parser.

CRITICAL ARCHITECTURE RULE (see SKILL.md): this parser produces
`scanner_alert` Observations ONLY. It must never produce, and has no way to
produce, a confirmed Finding — a nuclei alert is an indication to
investigate, not a proven vulnerability.

Based on nuclei's documented JSONL schema (stable public fields):
`template-id`, `info.name`, `info.severity`, `host`, `matched-at`, `type`.
"""

from __future__ import annotations

import json

from adi.knowledge.observations import Observation, ObservationType


def parse(stdout: str, stderr: str, context: dict) -> list[Observation]:
    observations: list[Observation] = []

    if not stdout.strip():
        if context.get("exit_code", 0) not in (0, None):
            observations.append(Observation(
                type=ObservationType.TOOL_ERROR,
                subject=context.get("target", ""),
                value={"tool": "nuclei", "stderr": stderr.strip()[:2000]},
                source="nuclei",
            ))
        return observations

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = finding.get("info", {})
        observations.append(Observation(
            type=ObservationType.SCANNER_ALERT,
            subject=finding.get("matched-at", finding.get("host", context.get("target", ""))),
            value={
                "template_id": finding.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "description": info.get("description", ""),
                "matched_at": finding.get("matched-at", ""),
                "scan_type": finding.get("type", ""),
            },
            source="nuclei",
            # a template match is a hint to investigate, not a fact —
            # always sub-1.0, never treated as confirmed by anything
            # downstream that respects confidence levels.
            confidence=0.4,
        ))

    return observations
