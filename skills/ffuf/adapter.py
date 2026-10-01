"""ffuf argv construction.

ffuf has no native "write JSON to stdout" flag, so this writes to
`/dev/stdout` (Unix-only) — acceptable since tools only ever run inside the
Linux-based isolated runtime.
"""

from __future__ import annotations

from adi.tools.wordlists import resolve_web_content_wordlist


def build_argv(target: str, parameters: dict, binary: str) -> list[str]:
    wordlist = resolve_web_content_wordlist(parameters.get("wordlist"))
    fuzz_url = target.rstrip("/") + "/FUZZ"
    argv = [
        binary, "-u", fuzz_url, "-w", wordlist,
        "-of", "json", "-o", "/dev/stdout",
        "-t", str(parameters.get("threads", 20)),
        "-s",  # silent: suppress the progress banner from stdout
    ]
    if parameters.get("filter_status"):
        argv += ["-fc", str(parameters["filter_status"])]
    return argv
