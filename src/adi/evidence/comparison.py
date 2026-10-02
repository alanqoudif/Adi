"""Deterministic response comparison (spec Phase 4 section 4), built on
Phase 3's response fingerprints.

A comparison is raw material for a hypothesis, never a verdict by itself —
see `adi.findings.verifier` for what else must be true before a difference
like this becomes a confirmed finding.
"""

from __future__ import annotations

from pydantic import BaseModel

from adi.http.fingerprints import fingerprint_response


class ResponseSnapshot(BaseModel):
    """What's compared — callers build this from an `HTTPExchange`/
    `HttpExchangeRecord` plus the raw body text it was computed from."""

    label: str  # e.g. "user_a", "anonymous"
    status: int
    headers: dict[str, str]
    content_type: str
    body: str


class ResponseComparison(BaseModel):
    label_a: str
    label_b: str
    status_a: int
    status_b: int
    status_match: bool
    content_type_match: bool
    content_length_delta: int
    body_hash_match: bool
    header_fingerprint_match: bool
    summary: str

    @property
    def responses_equivalent(self) -> bool:
        """Status and body match — the strongest deterministic signal that
        two sessions received the "same" protected content. Still not a
        verdict: see the authorization validator for ownership reasoning."""
        return self.status_match and self.body_hash_match


def compare_responses(a: ResponseSnapshot, b: ResponseSnapshot) -> ResponseComparison:
    fp_a = fingerprint_response(a.status, a.headers, a.body, a.content_type)
    fp_b = fingerprint_response(b.status, b.headers, b.body, b.content_type)

    status_match = a.status == b.status
    content_type_match = fp_a.content_type == fp_b.content_type
    body_hash_match = fp_a.normalized_body_hash == fp_b.normalized_body_hash
    header_fingerprint_match = fp_a.header_fingerprint == fp_b.header_fingerprint

    bits = []
    bits.append(f"status {'matches' if status_match else 'differs'} ({a.status} vs {b.status})")
    bits.append(f"body {'matches' if body_hash_match else 'differs'}")
    summary = f"{a.label} vs {b.label}: " + ", ".join(bits)

    return ResponseComparison(
        label_a=a.label, label_b=b.label, status_a=a.status, status_b=b.status,
        status_match=status_match, content_type_match=content_type_match,
        content_length_delta=fp_a.content_length - fp_b.content_length,
        body_hash_match=body_hash_match, header_fingerprint_match=header_fingerprint_match,
        summary=summary,
    )
