"""Markdown rendering of a `Report`. Pure function of the report model."""

from __future__ import annotations

from adi.reporting.models import FindingReport, Report


def _finding_block(f: FindingReport) -> list[str]:
    lines = [
        f"### {f.display_id} — {f.title}", "",
        f"- **Severity:** {f.severity.upper()}",
        f"- **Confidence:** {f.confidence:.2f}",
        f"- **Status:** {f.status}",
        f"- **Category:** {f.category}",
        f"- **Affected component:** {f.affected_component}",
        f"- **Security property:** {f.security_property}", "",
        "**Description**", "", f.description or "(none)", "",
        "**Observed behavior**", "",
    ]
    lines += [f"- {o}" for o in f.observed_behavior] or ["- (none recorded)"]
    lines += ["", "**Expected secure behavior**", "", f.expected_secure_behavior or "(n/a)", "",
              "**Validation performed**", ""]
    lines += [f"- {v}" for v in f.validation_performed] or ["- (none recorded)"]
    lines += ["", "**Evidence**", "", ", ".join(f.evidence_ids) or "(none)", "",
              "**Impact**", "", f.impact or "(not characterized)", "",
              "**Remediation**", "", f.remediation or "(none)", "",
              "**References**", ""]
    lines += [f"- {r}" for r in f.references] or ["- (none)"]
    lines += ["", f"**Critic review:** {f.critic_summary}", ""]
    return lines


def render_markdown(r: Report) -> str:
    a, ex = r.assessment, r.executive_summary
    out = ["# Adi Security Assessment", "",
           f"*Assessment `{a['id']}` — {a['name']} ({a['mode']}) — generated {a['generated_at']}*", "",
           "## Executive Summary", "",
           f"Goal: {a['goal']}", "",
           f"- Assets assessed: {ex['assets_assessed']}",
           f"- Endpoints observed: {ex['endpoints_observed']}",
           f"- Hypotheses evaluated: {ex['hypotheses_evaluated']}",
           f"- Findings confirmed: {ex['findings_confirmed']}",
           f"- Supported / needing review: {ex['supported_needing_review']}",
           f"- Hypotheses rejected: {ex['hypotheses_rejected']}",
           f"- Positive controls observed: {ex['positive_controls_observed']}", "",
           "Figures above are counts of stored assessment records.", "",
           "## Scope", ""]
    s = r.scope
    out += [f"- Targets: {', '.join(s['targets']) or 'none'}",
            f"- Excluded hosts: {', '.join(s['excluded_hosts']) or 'none'}",
            f"- Active validation permitted: {s['permissions'].get('active_validation')}",
            f"- Authentication testing permitted: {s['permissions'].get('authentication_testing')}",
            f"- Test identities: {', '.join(t['name'] for t in s['test_accounts']) or 'anonymous only'}",
            "", "## Methodology", ""]
    out += [f"{i}. {m}" for i, m in enumerate(r.methodology, 1)]
    sf = r.attack_surface
    out += ["", "## Attack Surface Summary", "",
            f"- Assets: {', '.join(sf['assets']) or 'none'}",
            f"- Services: {', '.join(sf['services']) or 'none'}",
            f"- Endpoints: {sf['endpoint_count']} ({sf['parameter_count']} parameters)",
            f"- Technologies: {', '.join(sf['technologies']) or 'none identified'}",
            f"- Sessions: {', '.join(sf['sessions'])}", ""]
    out += [f"  - `{e}`" for e in sf["endpoints"][:50]]
    out += ["", "## Confirmed Findings", ""]
    if r.findings:
        for f in r.findings:
            out += _finding_block(f)
    else:
        out += ["No findings were confirmed.", ""]
    out += ["## Supported / Needs Review", ""]
    if r.supported_items:
        for f in r.supported_items:
            out += [(f"- **{f.display_id}** {f.title} — {f.severity}, {f.status} "
                    f"({f.validation_summary})")]
        out.append("")
    else:
        out += ["None.", ""]
    out += ["## Rejected Hypotheses Summary", ""]
    out += ([f"- **{h.display_id}** {h.title} — {h.reason}" for h in r.rejected_hypotheses]
            or ["None."])
    out += ["", "## Positive Security Controls Observed", ""]
    out += ([f"- **{p.display_id}** {p.title} (`{p.endpoint}`) — {p.summary}"
             for p in r.positive_security_observations] or ["None recorded."])
    out += ["", "## Recommendations", ""]
    out += [f"{i}. {x}" for i, x in enumerate(r.recommendations, 1)] or ["None."]
    out += ["", "## Evidence Index", "", "| ID | Type | Source | Subject | Hash |", "|---|---|---|---|---|"]
    out += [f"| {e.display_id} | {e.type} | {e.source} | {e.subject} | `{e.hash[:12]}` |"
            for e in r.evidence_index]
    act = r.activity_summary
    out += ["", "## Activity Summary", "",
            f"- Actions: {act['actions_total']}", f"- HTTP exchanges: {act['http_exchanges']}",
            f"- Validation actions: {act['validation_actions']}",
            f"- Critic reviews: {act['critic_reviews']}",
            f"- Hypotheses by status: {act['hypotheses_by_status']}", ""]
    return "\n".join(out)
