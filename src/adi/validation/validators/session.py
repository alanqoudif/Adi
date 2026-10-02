"""SessionValidator — cookie hardening and session-lifecycle checks (spec
Phase 4 section 12).

Cookie attribute checks are fully deterministic: Adi reads the actual
`Set-Cookie` metadata (never speculates) and only flags a cookie whose name
looks session/auth-related, so a throwaway analytics cookie missing
`Secure` doesn't get reported the same way a session cookie would.
"""

from __future__ import annotations

from adi.evidence.models import EvidenceType
from adi.http.models import HTTPMethod
from adi.validation.models import ValidationActionType, ValidationOutcome, ValidationResult

_SENSITIVE_COOKIE_NAME_HINTS = ("session", "sid", "token", "auth", "jwt")


def _looks_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SENSITIVE_COOKIE_NAME_HINTS)


class SessionValidator:
    def __init__(self, ctx):
        self.ctx = ctx

    async def check_cookie_attributes(
        self, url: str, hypothesis_id: str, method: HTTPMethod | str = "GET",
        body: str | None = None, session_id: str = "anonymous",
    ) -> ValidationResult:
        exchange, _ = await self.ctx.http_workspace.fetch_with_exchange(
            method, url, session_id=session_id, body=body, source="validator_session",
        )
        if exchange.error or exchange.response is None:
            evidence = self.ctx.evidence_store.create(
                EvidenceType.HTTP_EXCHANGE, source="validator_session", subject=url,
                summary=f"request error: {exchange.error}", raw_text=exchange.error or "",
                related_hypothesis_ids=[hypothesis_id],
            )
            return ValidationResult(
                action_type=ValidationActionType.CHECK_COOKIE_ATTRIBUTE,
                outcome=ValidationOutcome.ERROR, detail=exchange.error or "no response",
                evidence_ids=[evidence.id],
            )

        sensitive_cookies = [c for c in exchange.response.cookies if _looks_sensitive(c.name)]
        issues = []
        for c in sensitive_cookies:
            missing = [flag for flag, present in (("Secure", c.secure), ("HttpOnly", c.http_only))
                       if not present]
            if missing:
                issues.append(f"{c.name}: missing {' and '.join(missing)}")

        summary = "; ".join(issues) if issues else "all session-like cookies have Secure+HttpOnly"
        evidence = self.ctx.evidence_store.create(
            EvidenceType.CONFIGURATION, source="validator_session", subject=url, summary=summary,
            raw_text="\n".join(
                f"{c.name}: Secure={c.secure} HttpOnly={c.http_only} SameSite={c.same_site or '(unset)'}"
                for c in exchange.response.cookies
            ),
            related_hypothesis_ids=[hypothesis_id],
            metadata={"cookie_count": len(exchange.response.cookies), "issue_count": len(issues)},
        )

        if not sensitive_cookies:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_COOKIE_ATTRIBUTE,
                outcome=ValidationOutcome.INCONCLUSIVE,
                detail="no session-like cookie was set by this request", evidence_ids=[evidence.id],
            )
        if issues:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_COOKIE_ATTRIBUTE,
                outcome=ValidationOutcome.SUPPORTS, detail=summary, evidence_ids=[evidence.id],
            )
        return ValidationResult(
            action_type=ValidationActionType.CHECK_COOKIE_ATTRIBUTE,
            outcome=ValidationOutcome.REFUTES, detail=summary, evidence_ids=[evidence.id],
        )

    async def check_session_invalidation(
        self, logout_url: str, protected_url: str, session_id: str, hypothesis_id: str,
    ) -> ValidationResult:
        """After logging out, does the same session cookie still reach the
        protected endpoint? (spec section 12 — "session still usable after
        logout")."""
        await self.ctx.http_workspace.fetch_with_exchange(
            "POST", logout_url, session_id=session_id, source="validator_session",
        )
        exchange, _ = await self.ctx.http_workspace.fetch_with_exchange(
            "GET", protected_url, session_id=session_id, source="validator_session",
        )
        status = exchange.response.status if exchange.response else None

        evidence = self.ctx.evidence_store.create(
            EvidenceType.HTTP_EXCHANGE, source="validator_session", subject=protected_url,
            summary=f"post-logout request -> {status}",
            raw_text=f"POST {logout_url} (logout)\nGET {protected_url} -> {status}",
            related_hypothesis_ids=[hypothesis_id],
        )

        if status is not None and status < 400:
            return ValidationResult(
                action_type=ValidationActionType.CHECK_SESSION_INVALIDATION,
                outcome=ValidationOutcome.SUPPORTS,
                detail=f"session remained usable after logout (status {status})",
                evidence_ids=[evidence.id],
            )
        return ValidationResult(
            action_type=ValidationActionType.CHECK_SESSION_INVALIDATION,
            outcome=ValidationOutcome.REFUTES,
            detail=f"session correctly invalidated after logout (status {status})",
            evidence_ids=[evidence.id],
        )
