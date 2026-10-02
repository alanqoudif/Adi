"""whatweb argv construction. Always JSON-to-stdout."""

from __future__ import annotations


def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    return [binary, "--no-errors", "--log-json=-", "-a", str(parameters.get("aggression", 3)), target]
