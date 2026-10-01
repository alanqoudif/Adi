"""Deterministic whatweb JSON parser.

Based on whatweb's documented `--log-json=-` schema: a JSON array, one
object per target, with a `plugins` map of plugin-name -> metadata.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from adi.knowledge.observations import Observation, ObservationType

_HIGH_CONFIDENCE_PLUGINS = {"HTTPServer", "X-Powered-By"}


def parse(stdout: str, stderr: str, context: dict) -> list[Observation]:
    observations: list[Observation] = []

    if not stdout.strip():
        if context.get("exit_code", 0) != 0:
            observations.append(Observation(
                type=ObservationType.TOOL_ERROR,
                subject=context.get("target", ""),
                value={"tool": "whatweb", "stderr": stderr.strip()[:2000]},
                source="whatweb",
            ))
        return observations

    try:
        results = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return [Observation(
            type=ObservationType.TOOL_ERROR, subject=context.get("target", ""),
            value={"tool": "whatweb", "error": f"JSON parse error: {exc}"}, source="whatweb",
        )]

    for entry in results:
        target_url = entry.get("target", context.get("target", ""))
        host = urlsplit(target_url).hostname or target_url
        for plugin_name, plugin_data in (entry.get("plugins") or {}).items():
            confidence = 1.0 if plugin_name in _HIGH_CONFIDENCE_PLUGINS else 0.6
            label = plugin_name
            strings = plugin_data.get("string") if isinstance(plugin_data, dict) else None
            if strings:
                label = strings[0]
            observations.append(Observation(
                type=ObservationType.TECHNOLOGY_FINGERPRINT,
                subject=host,
                value={"name": label, "confidence": "high" if confidence == 1.0 else "medium",
                       "source": "whatweb_plugin", "plugin": plugin_name},
                source="whatweb",
                confidence=confidence,
            ))

    return observations
