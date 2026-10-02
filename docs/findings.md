# Hypotheses, findings and positive controls

Use `adi hypotheses <id>` and `adi hypothesis <id> ADI-H-001` to inspect a security
question, supporting/contradicting evidence, validation plan, action reasons,
remaining persistent budget and related findings. Use `adi findings <id>` and
`adi finding <id> ADI-F-001` for findings and their impact, remediation and critic.

A confirmed finding requires a persisted hypothesis and evidence, a supporting
scope-authorized validation record tied to that evidence, and an accepted critic
review when the pipeline policy requires one. Confirmation fails if these are
missing. Scanner evidence alone is supported; contrary controlled evidence rejects
the hypothesis. Inconclusive tests remain unresolved. This preserves false-positive
rejection instead of hiding rejected indications from assessment history.

Severity is calculated from structured impact/exploitability factors using
conservative category defaults. Model prose cannot set CRITICAL. Header hardening
is INFO/LOW; controlled cross-user authorization receives the configured impact-based
severity (High in the local lab). These defaults are not a full CVSS implementation
or a claim about business impact. Confidence describes evidence support separately
from severity. The pipeline deduplicates category + overlapping endpoint and merges
evidence from scanners/validators.

PositiveSecurityObservations are stored in their own table with ID, category,
title, summary, asset, endpoint, session, evidence IDs and timestamp. A refuting
validation records the specific secure behavior tested: denied cross-user access,
anonymous rejection, role enforcement, logout behavior, cookie protections,
headers, or the tested CORS restriction. They never create Findings and appear in
status and reports. Absence of one tested failure does not certify an entire control.
For example, the cookie check currently assesses Secure/HttpOnly; it does not assert
that every SameSite configuration is secure. Rate-limit observations can be recorded
through the workspace API; an automated rate-limit validator is not available yet.
