"""Wordlist resolution for content-discovery tools (spec Phase 3J).

Never hard-codes one machine-specific SecLists path. Checks the configured
path first, then a handful of common Kali/Homebrew install locations. No
wordlist is bundled in this package — a tiny one for tests/local
development lives under `tests/fixtures/wordlists/` instead (never commit a
real, large wordlist to the repo).
"""

from __future__ import annotations

from pathlib import Path

_COMMON_WEB_CONTENT_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/homebrew/share/wordlists/dirb/common.txt",
]


class WordlistNotFoundError(FileNotFoundError):
    pass


def resolve_web_content_wordlist(configured_path: str | None = None) -> str:
    if configured_path and Path(configured_path).is_file():
        return configured_path
    for candidate in _COMMON_WEB_CONTENT_PATHS:
        if Path(candidate).is_file():
            return candidate
    raise WordlistNotFoundError(
        "no web-content wordlist found — set wordlists.web_content in .adi.yaml, "
        "or install SecLists/dirb (e.g. `apt install seclists` or `brew install seclists`)"
    )
