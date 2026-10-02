"""feroxbuster argv construction. Always JSONL-to-stdout so the parser never
has to deal with feroxbuster's human-readable progress output."""

from __future__ import annotations

from adi.tools.wordlists import resolve_web_content_wordlist


def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    wordlist = resolve_web_content_wordlist(parameters.get("wordlist"))
    argv = [
        binary, "-u", target, "-w", wordlist,
        "--json", "--silent", "--no-state", "--scan-limit", "1",
        "-t", str(parameters.get("threads", 20)),
        "-d", str(parameters.get("depth", 1)),
    ]
    argv += ['-rate' if 'ffuf' in binary else '--rate-limit', str(parameters.get('rate', 5))]
    if parameters.get("extensions"):
        argv += ["-x", ",".join(parameters["extensions"])]
    return argv
