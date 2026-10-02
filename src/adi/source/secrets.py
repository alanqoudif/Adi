"""Detect presence, hash values, redact BEFORE persistence or retrieval."""
import hashlib
import math
import re
from collections import Counter

from adi.source.models import SecretStatus, SourceSecretIndication

_PATTERNS = [
    ('private_key', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----')),
    ('credential', re.compile(
        r'''(?i)(?:[\"']?(?:[\w-]*(?:secret|token|password|passwd|api[_-]?key)[\w-]*)[\"']?\s*[=:]\s*[\"'])([^\"'\n]{4,})(?=[\"'])''')),
    ('credential', re.compile(r'(?im)^\s*(?:[\w-]*(?:SECRET|TOKEN|PASSWORD|API_KEY)[\w-]*)\s*=\s*([^\s\"\'#$]{4,})')),
    ('database_url', re.compile(r'(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^:\s/]+:([^@\s]+)@')),
    ('provider_token', re.compile(r'\b(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,})\b')),
]


def secret_matches(text: str):
    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span(1) if match.lastindex else match.span()
            value = text[start:end]
            if value in ('<redacted>', 'REDACTED') or value.startswith(('${', '{{')):
                continue
            yield kind, start, end, value


def scan_secrets(text: str, path: str, tool: str = 'builtin') -> list[SourceSecretIndication]:
    found = {}
    for kind, start, end, value in secret_matches(text):
        fingerprint = hashlib.sha256(value.encode()).hexdigest()
        counts = Counter(value)
        entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())
        line = text.count('\n', 0, start) + 1
        found[(line, fingerprint)] = SourceSecretIndication(
            type=kind, file=path, line=line, fingerprint=fingerprint, entropy=entropy,
            confidence=1.0, source_tool=tool, status=SecretStatus.CONFIRMED_PRESENT,
            test_only='fake' in value.lower() or 'test' in value.lower(),
        )
    return list(found.values())


def redact_code(text: str) -> str:
    spans = sorted({(start, end) for _, start, end, _ in secret_matches(text)}, reverse=True)
    # Merge overlapping detections before replacement; preserve line numbering.
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        text = text[:start] + '<redacted>' + '\n' * text[start:end].count('\n') + text[end:]
    return text
