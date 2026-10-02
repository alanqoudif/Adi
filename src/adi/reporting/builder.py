"""ReportBuilder: assembles a `Report` entirely from persisted workspace
state — no in-memory objects from the original run are needed, so a report
can be regenerated after a resume (spec Phase 4 section 20). Every figure in
the executive summary is a stored fact, never an inference."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from adi.findings.pipeline import _CATEGORY_GUIDANCE
from adi.knowledge.workspace import Workspace
from adi.reporting.ids import display_id_map
from adi.reporting.models import (
    EvidenceIndexEntry,
    FindingReport,
    PositiveObservationReport,
    RejectedHypothesisReport,
    Report,
)
from adi.reporting.redaction import known_secrets, redact_structure

METHODOLOGY = [
    ("Discovery: the web attack surface was mapped from the authorized root URL using "
    "Adi's own HTTP/HTML analysis and, where available, content-discovery tools."),
    ("Hypothesis: observations were turned into explicit, falsifiable security hypotheses. "
    "Scanner alerts and suspicious responses are indications only, never findings."),
    ("Validation: each hypothesis was tested with a minimal, controlled, scope-enforced "
    "validation action, stopping as soon as the question was answered."),
    ("Review: a finding is confirmed only with reproducible evidence, no contradicting "
    "evidence, and (where configured) critic review. Rejected hypotheses are retained."),
]

# category -> (security property, expected secure behavior, references)
_PROPERTIES: dict[str, tuple[str, str, list[str]]] = {
    "broken_object_authorization": (
        "Object-level authorization (resource ownership)",
        "A session that does not own an object receives 401/403/404 for it.",
        ["OWASP API Security Top 10 — API1: Broken Object Level Authorization",
         "CWE-639: Authorization Bypass Through User-Controlled Key"]),
    "broken_function_authorization": (
        "Function-level authorization (role enforcement)",
        "A normal-privilege session is denied privileged functions (401/403).",
        ["OWASP API Security Top 10 — API5: Broken Function Level Authorization",
         "CWE-285: Improper Authorization"]),
    "missing_authentication": (
        "Authentication boundary",
        "Protected endpoints return 401/403 to unauthenticated requests.",
        ["OWASP API Security Top 10 — API2: Broken Authentication",
         "CWE-306: Missing Authentication for Critical Function"]),
    "cookie_hardening": (
        "Session cookie protection",
        "Session cookies set Secure, HttpOnly and an appropriate SameSite value.",
        ["OWASP Session Management Cheat Sheet", "CWE-614 / CWE-1004"]),
    "cors_misconfiguration": (
        "Cross-origin access control",
        "Credentialed CORS is allowed only for an explicit allow-list of origins.",
        ["OWASP HTML5 Security Cheat Sheet — CORS", "CWE-942"]),
    "information_disclosure": (
        "Information exposure",
        "Errors return a generic message; internals are logged server-side only.",
        ["OWASP Error Handling Cheat Sheet", "CWE-209: Error Message Containing Sensitive Information"]),
    "missing_security_header": (
        "Defense-in-depth HTTP headers",
        "Responses include the security headers appropriate to the application.",
        ["OWASP Secure Headers Project"]),
}


def _json(value, default):
    try:
        return json.loads(value) if value else default
    except json.JSONDecodeError:
        return default


class ReportBuilder:
    def __init__(self, workspace: Workspace):
        self.ws = workspace

    def build(self) -> Report:
        ws = self.ws
        scope = ws.load_scope()
        hypotheses = ws.list_hypotheses()
        findings = ws.list_findings()
        evidence = ws.list_evidence()
        positives = ws.list_positive_observations()
        validations = ws.list_validation_actions()
        reviews = ws.list_critic_reviews()
        endpoints = ws.list_endpoints()
        observations = ws.list_observations()

        f_ids = display_id_map(findings, "ADI-F")
        h_ids = display_id_map(hypotheses, "ADI-H")
        ev_ids = display_id_map(evidence, "EV")
        pos_ids = display_id_map(positives, "ADI-P")

        def finding_report(f) -> FindingReport:
            prop, expected, refs = _PROPERTIES.get(
                f.category, (f.category or "Security property", "", []))
            vals = [v for v in validations if v.hypothesis_id == f.hypothesis_id]
            review = next((r for r in reversed(reviews) if r.hypothesis_id == f.hypothesis_id), None)
            critic = ""
            if review:
                critic = f"{review.decision}"
                concerns = _json(review.concerns_json, [])
                if concerns:
                    critic += " — concerns: " + "; ".join(concerns)
            endpoints_list = _json(f.affected_endpoints_json, [])
            return FindingReport(
                display_id=f_ids[f.id], id=f.id, hypothesis_id=f.hypothesis_id,
                validation_ids=[v.id for v in vals], critic_review_id=f.critic_review_id,
                affected_assets=_json(f.affected_assets_json, []), title=f.title, severity=f.severity,
                confidence=round(f.confidence, 2), status=f.status, category=f.category,
                affected_component=", ".join(endpoints_list) or "n/a",
                affected_endpoints=endpoints_list, affected_roles=_json(f.affected_roles_json, []),
                security_property=prop, description=f.summary,
                observed_behavior=[v.detail for v in vals if v.outcome == "supports"],
                expected_secure_behavior=expected,
                validation_performed=[
                    f"{v.action_type}: {v.outcome} — {v.reason_summary or v.detail}" for v in vals],
                evidence_ids=[ev_ids.get(e, e) for e in _json(f.evidence_ids_json, [])],
                impact=f.impact, remediation=f.remediation, references=refs,
                critic_summary=critic or "no critic review recorded",
                validation_summary=f.validation_summary,
            )

        confirmed = [finding_report(f) for f in findings if f.status == "confirmed"]
        supported = [finding_report(f) for f in findings if f.status in ("supported", "indicated")]

        rejected = []
        for h in hypotheses:
            if h.status != "rejected":
                continue
            vals = [v for v in validations if v.hypothesis_id == h.id]
            reason = "; ".join(v.detail for v in vals if v.outcome == "refutes") or "rejected by verifier"
            rejected.append(RejectedHypothesisReport(
                display_id=h_ids[h.id], title=h.title, category=h.category, reason=reason,
                evidence_ids=[ev_ids.get(e, e) for e in _json(h.contradicting_observation_ids_json, [])]))

        positive_reports = [
            PositiveObservationReport(
                display_id=pos_ids[p.id], id=p.id, asset=p.asset, created_at=str(p.created_at), category=p.category, title=p.title, summary=p.summary,
                endpoint=p.endpoint, session=p.session,
                evidence_ids=[ev_ids.get(e, e) for e in _json(p.evidence_ids_json, [])])
            for p in positives]

        recs: list[str] = []
        for fr in confirmed + supported:
            if fr.remediation and fr.remediation not in recs:
                recs.append(fr.remediation)

        technologies = sorted({o.value.get("name") for o in observations
                               if o.type == "technology_fingerprint" and o.value.get("name")})
        hyp_counts: dict[str, int] = {}
        for h in hypotheses:
            hyp_counts[h.status] = hyp_counts.get(h.status, 0) + 1

        attack_surface = {
            "assets": [h.address for h in ws.list_hosts()],
            "services": [f"{s.port}/{s.protocol} {s.name}".strip() for s in ws.list_services()],
            "endpoint_count": len(endpoints),
            "parameter_count": sum(len(ws.list_parameters(e.id)) for e in endpoints),
            "endpoints": [f"{'/'.join(_json(e.methods_json, []))} {e.path}"
                          for e in sorted(endpoints, key=lambda e: e.path)][:100],
            "technologies": technologies,
            "sessions": [s.name for s in ws.list_sessions()],
        }
        executive = {
            "assets_assessed": len(attack_surface["assets"]),
            "endpoints_observed": len(endpoints),
            "hypotheses_evaluated": len({v.hypothesis_id for v in validations}),
            "findings_confirmed": len(confirmed),
            "supported_needing_review": len(supported),
            "hypotheses_rejected": len(rejected),
            "positive_controls_observed": len(positives),
        }
        activity = {
            "actions_total": len(ws.list_actions()),
            "http_exchanges": len(ws.list_http_exchanges()),
            "validation_actions": len(validations),
            "critic_reviews": len(reviews),
            "evidence_items": len(evidence),
            "hypotheses_by_status": hyp_counts,
        }
        report = Report(
            assessment={"id": ws.assessment_id, "name": scope.name, "mode": scope.mode.value,
                        "goal": scope.goal, "status": ws.assessment_status(), "generated_at": datetime.now(UTC).isoformat()},
            scope={"targets": scope.targets, "allowed_ips": scope.allowed_ips,
                   "excluded_hosts": scope.excluded_hosts,
                   "permissions": scope.permissions.model_dump(),
                   "rate_limits": scope.rate_limits.model_dump(),
                   "test_accounts": [{"name": a.name, "role": a.role} for a in scope.test_accounts]},
            attack_surface=attack_surface, executive_summary=executive, methodology=METHODOLOGY,
            findings=confirmed, supported_items=supported, rejected_hypotheses=rejected,
            positive_security_observations=positive_reports, recommendations=recs,
            evidence_index=[EvidenceIndexEntry(
                display_id=ev_ids[e.id], id=e.id, type=e.type, source=e.source, subject=e.subject,
                summary=e.summary, hash=e.hash, timestamp=str(e.created_at),
                raw_reference=e.raw_reference,
                http_exchange_ids=_json(e.metadata_json, {}).get("http_exchange_ids", [])) for e in evidence],
            activity_summary=activity,
        )
        return Report.model_validate(redact_structure(report.model_dump(), known_secrets(scope)))


__all__ = ["_CATEGORY_GUIDANCE", "ReportBuilder"]
