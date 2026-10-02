"""Deterministic hashing for evidence integrity (spec Phase 4 section 3).

Lets a report point to exactly which captured artifact produced a claim —
"HTTP exchange EX-183, hash abcd1234" — instead of relying on generated
prose alone.
"""

from __future__ import annotations

import hashlib


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def short_hash(full_hash: str, length: int = 12) -> str:
    return full_hash[:length]
