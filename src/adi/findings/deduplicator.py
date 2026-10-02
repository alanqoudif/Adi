"""FindingDeduplicator (spec Phase 4 section 30).

If a nuclei indication and an HTTP validator both point at the same
(category, endpoint) security property, that must become ONE finding with
merged evidence — never two.
"""

from __future__ import annotations

import json

from adi.knowledge.db import FindingRecord
from adi.knowledge.workspace import Workspace


class FindingDeduplicator:
    def __init__(self, workspace: Workspace):
        self.workspace = workspace

    def find_duplicate(self, category: str, affected_endpoints: list[str]) -> FindingRecord | None:
        endpoint_set = set(affected_endpoints)
        for finding in self.workspace.list_findings():
            if finding.category != category:
                continue
            existing_endpoints = set(json.loads(finding.affected_endpoints_json))
            if existing_endpoints & endpoint_set:
                return finding
        return None

    def merge_evidence(self, finding_id: str, evidence_ids: list[str]) -> None:
        finding = self.workspace.get_finding(finding_id)
        if finding is None:
            raise ValueError(f"no finding '{finding_id}'")
        existing = json.loads(finding.evidence_ids_json)
        merged = existing + [e for e in evidence_ids if e not in existing]
        self.workspace.update_finding(finding_id, evidence_ids_json=json.dumps(merged))
        for evidence_id in evidence_ids:
            self.workspace.link_evidence_to_finding(evidence_id, finding_id)
