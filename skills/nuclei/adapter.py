"""nuclei argv construction. Always JSONL-to-stdout, silent (no banner)."""

from __future__ import annotations


def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    argv = [binary, "-u", target, "-jsonl", "-silent"]
    if parameters.get("severity"):
        argv += ["-severity", parameters["severity"]]
    if parameters.get("tags"):
        argv += ["-tags", parameters["tags"]]
    if parameters.get("rate_limit"):
        argv += ["-rate-limit", str(parameters["rate_limit"])]
    return argv
