# Evidence

EvidenceStore owns evidence creation, sanitization and hashing. Evidence has a
persistent ID, type, source, subject, timestamp, confidence, summary, original
content SHA-256, related hypotheses/findings, raw reference and bounded preview.
HTTP validation evidence explicitly references the persisted HTTP exchange IDs;
validation IDs connect it to the action history. Hashes are computed before
redaction. Preview text is not the original payload and cannot reproduce that hash.

```bash
adi evidence <assessment-id>
adi evidence <assessment-id> EV-001
```

The first command shows a concise Rich table; the second shows sanitized metadata
and at most 2,000 preview characters, with exchange references. Neither opens or
dumps raw response files. Display IDs derive from creation order and accept either
friendly IDs or persistent IDs across resume.

Authorization, Cookie, Set-Cookie, Bearer/Basic credentials, API-key-like strings,
password assignments and configured test-account password values are scrubbed at
export boundaries. Structured credential keys are redacted too. Stored action
parameters and evidence previews receive the same protection. Reports never contain
full evidence payloads or cookie jars. Pattern redaction cannot identify every
arbitrary unlabelled secret; configured credential values are also matched exactly.

The HTTP workspace's raw local response artifacts are sensitive assessment data,
not export-safe report content. Restrict access to `.adi/`; do not publish it wholesale.
