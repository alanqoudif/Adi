"""Tiny, deterministic natural-language scope interpreter.

This is intentionally NOT an LLM: scope is the authorization boundary, and
the product spec requires that "the model cannot silently expand scope."
Keeping this a small deterministic matcher means scope changes are
reproducible, auditable, and can never be influenced by a prompt-injected
tool/HTTP response. Anything it doesn't recognize is left to the operator
to express as an explicit `/scope` command instead.

Each matcher returns a human-readable description of the *proposed*
change plus a callable to apply it — the caller (plain shell / TUI) is
responsible for showing the proposal and getting explicit confirmation
before calling `apply()`. This function only ever narrows/adjusts, never
auto-applies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from adi.scope.models import Scope


@dataclass
class ScopeProposal:
    description: str
    fields: dict


_ONLY_HOST_RE = re.compile(r"^(only|just)\s+(.+)$", re.IGNORECASE)
_INCLUDE_RE = re.compile(r"^(include|add)\s+(.+)$", re.IGNORECASE)
_NO_AUTH_RE = re.compile(r"(don'?t|do not|no)\s+(do\s+)?(perform\s+)?auth(entication)?\s*test", re.IGNORECASE)
_YES_AUTH_RE = re.compile(r"(enable|allow|turn on)\s+auth(entication)?\s*test", re.IGNORECASE)


def interpret_scope_command(text: str, current: Scope) -> ScopeProposal | None:
    text = text.strip()

    match = _ONLY_HOST_RE.match(text)
    if match:
        target = match.group(2).strip()
        return ScopeProposal(
            description=f"Restrict authorized targets to only: {target}",
            fields={"targets": [target]},
        )

    match = _INCLUDE_RE.match(text)
    if match:
        target = match.group(2).strip()
        targets = list(current.targets)
        if target not in targets:
            targets.append(target)
        return ScopeProposal(
            description=f"Add '{target}' to authorized targets (now: {', '.join(targets)})",
            fields={"targets": targets},
        )

    if _NO_AUTH_RE.search(text):
        permissions = current.permissions.model_copy(update={"authentication_testing": False})
        return ScopeProposal(
            description="Disable authentication testing for this assessment",
            fields={"permissions": permissions},
        )

    if _YES_AUTH_RE.search(text):
        # Authentication testing is explicitly gated OFF by default and the
        # model can never enable it — but an operator typing this directly
        # at the scope prompt is the one case it's allowed, and even then
        # the Permissions flag alone does not unlock attempt budgets/rate;
        # those remain separate, narrower config the operator must also set.
        permissions = current.permissions.model_copy(update={"authentication_testing": True})
        return ScopeProposal(
            description=(
                "Enable authentication testing (budgets/rate limits still apply; "
                "this does not by itself authorize credential spraying)"
            ),
            fields={"permissions": permissions},
        )

    return None
