"""Deterministic response fingerprinting (spec Phase 3N).

Infrastructure for Phase 4's comparison-based validation (e.g. "does this
response differ between user_a and user_b"). A fingerprint is NOT a
vulnerability signal by itself — it is only ever raw material for later
comparison.
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel

_FINGERPRINT_HEADERS = ("content-type", "server", "x-powered-by", "www-authenticate")


class ResponseFingerprint(BaseModel):
    status: int
    content_type: str
    content_length: int
    normalized_body_hash: str
    header_fingerprint: str


def normalize_body_for_hash(body: str) -> str:
    """Strip whitespace-only differences so two responses that differ only
    in incidental formatting still hash identically."""
    return "\n".join(line.strip() for line in body.strip().splitlines() if line.strip())


def fingerprint_response(
    status: int, headers: dict[str, str], body: str, content_type: str = "",
) -> ResponseFingerprint:
    normalized = normalize_body_for_hash(body)
    body_hash = hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()

    lower_headers = {k.lower(): v for k, v in headers.items()}
    header_blob = "|".join(f"{h}={lower_headers.get(h, '')}" for h in _FINGERPRINT_HEADERS)
    header_fp = hashlib.sha256(header_blob.encode()).hexdigest()[:16]

    return ResponseFingerprint(
        status=status,
        content_type=content_type or lower_headers.get("content-type", ""),
        content_length=len(body),
        normalized_body_hash=body_hash,
        header_fingerprint=header_fp,
    )
