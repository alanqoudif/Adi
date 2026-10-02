"""Shared final redaction boundary for CLI, context and reports."""
from __future__ import annotations

import os
import re

from adi.evidence.redaction import redact_secrets

_SENSITIVE_KEY = re.compile(
    r"authorization|cookie|set-cookie|proxy-authorization|password|passwd|"
    r"secret|token|api[_-]?key", re.IGNORECASE)
_HEADER = re.compile(
    r"(?i)((?:authorization|cookie|set-cookie|proxy-authorization|x-api-key)"
    r"[\"']?\s*[:=]\s*)([^\r\n]+)")
_ASSIGNMENT = re.compile(
    r"(?i)((?:password|passwd|secret|token|api[_-]?key)[\"']?\s*[:=]\s*"
    r"[\"']?)([^\s\"'&,;}]+)")
_BEARER = re.compile(r"(?i)(Bearer\s+)[^\s\"',;]+")
_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{20,})\b")


def known_secrets(scope=None) -> tuple[str, ...]:
    names = [a.password_env for a in scope.test_accounts if a.password_env] if scope else []
    names += [k for k in os.environ if _SENSITIVE_KEY.search(k)]
    return tuple({os.environ[n] for n in names if os.environ.get(n)})


def redact_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    text = _HEADER.sub(lambda m: m.group(1) + "<redacted>", text)
    text = _ASSIGNMENT.sub(lambda m: m.group(1) + "<redacted>", text)
    text = _BEARER.sub(lambda m: m.group(1) + "<redacted>", text)
    text = _KEY.sub("<redacted>", text)
    return redact_secrets(text)


def redact_structure(obj, secrets: tuple[str, ...] = ()):
    if isinstance(obj, str):
        return redact_text(obj, secrets)
    if isinstance(obj, dict):
        return {k: "<redacted>" if _SENSITIVE_KEY.fullmatch(str(k)) else
                redact_structure(v, secrets) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_structure(v, secrets) for v in obj]
    return obj
