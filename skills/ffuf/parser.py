"""Deterministic ffuf JSON parser.

Based on ffuf's documented `-of json` schema: a single JSON document with a
top-level `results` array, each entry carrying `url`, `status`, and `host`.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from adi.knowledge.observations import Observation, ObservationType


def parse(stdout: str, stderr: str, context: dict) -> list[Observation]:
    observations: list[Observation] = []

    if not stdout.strip():
        if context.get("exit_code", 0) != 0:
            observations.append(Observation(
                type=ObservationType.TOOL_ERROR,
                subject=context.get("target", ""),
                value={"tool": "ffuf", "stderr": stderr.strip()[:2000]},
                source="ffuf",
            ))
        return observations

    try:
        document = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return [Observation(
            type=ObservationType.TOOL_ERROR, subject=context.get("target", ""),
            value={"tool": "ffuf", "error": f"JSON parse error: {exc}"}, source="ffuf",
        )]

    for result in document.get("results", []):
        status = result.get("status")
        if status is None or status == 404:
            continue
        url = result.get("url", "")
        host = result.get("host") or urlsplit(url).hostname or ""
        path = urlsplit(url).path or "/"

        observations.append(Observation(
            type=ObservationType.WEB_ENDPOINT,
            subject=f"{host}{path}",
            value={"host": host, "path": path, "methods": ["GET"], "requires_auth": status == 401,
                   "status": status},
            source="ffuf",
            confidence=1.0,
        ))

    return observations
