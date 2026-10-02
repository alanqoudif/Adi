"""Deterministic feroxbuster JSONL parser.

Verified against real `feroxbuster --json --silent` output (v2.13.1):
one JSON object per line, `"type": "response"` for each HTTP response
observed. A 404 means the path doesn't exist and is not stored as an
endpoint; anything else (200, 301, 403, ...) is attack surface.
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
                value={"tool": "feroxbuster", "stderr": stderr.strip()[:2000]},
                source="feroxbuster",
            ))
        return observations

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") != "response":
            continue

        status = event.get("status")
        if status is None or status == 404:
            continue

        url = event.get("url", "")
        path = event.get("path") or urlsplit(url).path or "/"
        host = urlsplit(url).hostname or ""
        method = event.get("method", "GET")

        observations.append(Observation(
            type=ObservationType.WEB_ENDPOINT,
            subject=f"{host}{path}",
            value={"host": host, "path": path, "methods": [method], "requires_auth": status == 401,
                   "status": status},
            source="feroxbuster",
            confidence=1.0,
        ))

    return observations
