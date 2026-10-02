"""Shared context every validator needs — HTTP access, evidence creation,
and the knowledge workspace (for session/sanity lookups)."""

from __future__ import annotations

from dataclasses import dataclass

from adi.evidence.store import EvidenceStore
from adi.http.workspace import HTTPWorkspace
from adi.knowledge.workspace import Workspace


@dataclass
class ValidationContext:
    http_workspace: HTTPWorkspace
    evidence_store: EvidenceStore
    workspace: Workspace
