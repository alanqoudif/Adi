"""Terminal escape / control-sequence sanitization.

Everything the Product layer renders that originated outside Adi's own
code — tool output, HTTP response bodies, source filenames/content,
finding/hypothesis titles derived from any of those, external service
banners — is untrusted. A naive `print()` of such text lets a malicious
target inject terminal control sequences: moving the cursor, rewriting
the window title, hiding/overwriting prior output, or (on vulnerable
terminal emulators) worse. This module strips that class of injection
before any untrusted string reaches the console.

This is deliberately separate from `adi.reporting.redaction` (secret
redaction) and `adi.evidence.redaction` — those protect *content
confidentiality*; this protects the *rendering surface itself*.
"""

from __future__ import annotations

import re
import unicodedata

# ESC-prefixed sequences: CSI (cursor/screen control), OSC (title/clipboard/
# hyperlinks), DCS, and bare two-byte escapes.
_ESC_SEQ_RE = re.compile(
    r"\x1b(?:"
    r"\[[0-?]*[ -/]*[@-~]"      # CSI ... final byte
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC ... BEL or ST
    r"|P[^\x1b]*\x1b\\"          # DCS ... ST
    r"|[@-Z\\-_]"                # single two-byte escape
    r")",
    re.DOTALL,
)

# C0 control characters other than tab/newline, plus DEL and C1 controls.
_CONTROL_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f\x80-\x9f]"
)


def sanitize_for_terminal(text: str) -> str:
    """Strip ANSI/VT escape sequences and raw control characters from
    untrusted text. Tab and newline are preserved; everything else that
    isn't a normal printable/whitespace character is dropped rather than
    passed through, since Adi has no legitimate reason to emit raw
    control bytes from external data."""
    if not text:
        return text
    text = unicodedata.normalize("NFC", text)
    text = _ESC_SEQ_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    return text
