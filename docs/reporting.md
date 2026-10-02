# Persistent assessment reports

```bash
adi report <assessment-id>                         # Markdown + JSON
adi report <assessment-id> --format markdown
adi report <assessment-id> --format json --output ./reports
adi resume <assessment-id>
adi report <assessment-id>                         # regenerates from SQLite
```

Default files are `.adi/assessments/<id>/reports/report.md` and `report.json`.
`--output` selects a directory. Invalid formats fail clearly. Rendering uses no
model calls and no temporary objects from the assessment run. Generation after
resume reads the same findings, critic, evidence, positives and validation history.
Resume displays persistent state; it does not silently rerun completed validation.
The orchestrator's `generate_report` action uses the same production builder.

Markdown contains Executive Summary, Scope, Methodology, Attack Surface Summary,
Confirmed Findings, Supported / Needs Review, Rejected Hypotheses Summary, Positive
Security Controls Observed, Recommendations, Evidence Index and Activity Summary.
Confirmed entries include severity/confidence, property, affected component,
observed/expected behavior, validation, evidence, impact, remediation, references
and critic summary. Supported indications are kept in a separate section.

JSON schema version `1.0` is defined in `src/adi/reporting/models.py` and exported
as `docs/report.schema.json`. Top-level fields are assessment, scope, attack_surface,
executive_summary, methodology, findings, supported_items, rejected_hypotheses,
positive_security_observations, recommendations, evidence_index and activity_summary.
Finding IDs retain both display and persistent identifiers, hypothesis/validation
and critic links; evidence index includes original hashes and HTTP exchange IDs.
Stable IDs support later comparison; generated_at deliberately changes on regeneration.
No SARIF converter or regression service is implemented in Phase 4.

Executive counts are calculated from stored hosts, endpoints, validated hypotheses,
confirmed findings, rejected hypotheses and positive observations. No business impact
is inferred. Output excludes full response bodies, request credentials and model
chain-of-thought. All text receives a final secret-redaction pass; see `evidence.md`.

Mandatory tests cover actual files, JSON parsing, confirmed/rejected separation,
positive observations, critic and evidence references, redaction, process restart,
report regeneration, orphan prevention and persistent validation limits.
