"""Evidence-based teaching reconstructed exclusively from durable metadata."""
from __future__ import annotations

import json

from adi.reporting.redaction import known_secrets, redact_structure

_LESSONS = {
    "broken_object_authorization": "Authentication alone does not authorize access to another user's object. Compare controlled identities and ownership.",
    "broken_function_authorization": "Privileged functions need server-side permission checks.",
    "missing_authentication": "Protected resources must reject anonymous requests.",
    "cookie_hardening": "Session cookies need appropriate transport and script-access protections.",
    "missing_security_header": "A missing defense-in-depth header is a hardening indication, not proof of exploitation.",
    "cors_misconfiguration": "Credentialed cross-origin requests require a trusted origin allow-list.",
}


def explain_hypothesis(workspace, hypothesis_id: str) -> dict[str, str]:
    h = next(h for h in workspace.list_hypotheses() if h.id == hypothesis_id)
    supporting = json.loads(h.supporting_observation_ids_json)
    contradicting = json.loads(h.contradicting_observation_ids_json)
    evidence = [e for e in workspace.list_evidence()
                if h.id in json.loads(e.related_hypothesis_ids_json)]
    actions = workspace.list_validation_actions(h.id)
    investigations = [a for a in workspace.list_actions()
                      if a.action_type in ("investigate_hypothesis", "update_hypothesis")
                      and (a.target == h.id or json.loads(a.parameters_json).get("title") == h.title)]
    observed = "; ".join(a.reason_summary for a in investigations if a.reason_summary)
    if not observed:
        observed = "; ".join(e.summary for e in evidence[:3]) or "No triggering observation recorded."
    decisions = [f.validation_summary for f in workspace.list_findings() if f.hypothesis_id == h.id]
    reviews = workspace.list_critic_reviews(h.id)
    why = "; ".join(decisions or [v.detail for v in actions])
    if reviews:
        why += "; critic: " + reviews[-1].decision
    result = {"confirmed": "Confirmed", "rejected": "Rejected"}.get(h.status, "Needs more evidence")
    data = {
        "Observed": observed,
        "Security question": h.title + " (" + h.category + ")",
        "Validation": "; ".join(f"{v.id}: {v.action_type} — {v.reason_summary or 'reason not recorded'}" for v in actions) or "None recorded.",
        "Result": result,
        "Why": why or "No decision reason recorded.",
        "Lesson": _LESSONS.get(h.category, "Separate an indication from reproducible evidence; retain contrary evidence."),
        "Evidence": ", ".join(dict.fromkeys(supporting + contradicting)),
    }
    from adi.source.repository import SourceWorkspace
    snapshot = SourceWorkspace(workspace).load()
    if snapshot:
        source_h = next((s for s in snapshot.hypotheses if s.hypothesis_id == h.id), None)
        if source_h:
            data["Source pattern"] = source_h.observation
            data["Runtime mapping"] = "; ".join(c.method + " " + c.runtime_path for c in snapshot.correlations if c.route_id == source_h.route_id) or "Not correlated"
            data["Secure implementation"] = "Check resource owner/user_id against authenticated principal before returning data; preserve explicit policy grants."
    return redact_structure(data, known_secrets(workspace.load_scope()))
