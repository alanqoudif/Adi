"""Stable, machine-readable report schema."""

from __future__ import annotations

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.1"


class FindingReport(BaseModel):
    display_id: str
    id: str
    title: str
    severity: str
    confidence: float
    status: str
    category: str
    hypothesis_id: str | None = None
    validation_ids: list[str] = Field(default_factory=list)
    critic_review_id: str | None = None
    affected_assets: list[str] = Field(default_factory=list)
    affected_component: str
    affected_endpoints: list[str] = Field(default_factory=list)
    affected_roles: list[str] = Field(default_factory=list)
    security_property: str = ""
    description: str = ""
    observed_behavior: list[str] = Field(default_factory=list)
    expected_secure_behavior: str = ""
    validation_performed: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    critic_summary: str = ""
    validation_summary: str = ""
    root_cause: dict = Field(default_factory=dict)
    source_locations: list[str] = Field(default_factory=list)
    affected_code: list[dict] = Field(default_factory=list)
    source_evidence: list[str] = Field(default_factory=list)
    runtime_evidence: list[str] = Field(default_factory=list)


class RejectedHypothesisReport(BaseModel):
    display_id: str
    title: str
    category: str
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class PositiveObservationReport(BaseModel):
    display_id: str
    id: str
    asset: str = ""
    created_at: str = ""
    category: str
    title: str
    summary: str
    endpoint: str = ""
    session: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class EvidenceIndexEntry(BaseModel):
    display_id: str
    id: str
    type: str
    source: str
    subject: str
    summary: str
    hash: str
    timestamp: str = ""
    raw_reference: str | None = None
    http_exchange_ids: list[str] = Field(default_factory=list)


class Report(BaseModel):
    schema_version: str = SCHEMA_VERSION
    assessment: dict
    scope: dict
    attack_surface: dict
    executive_summary: dict
    methodology: list[str]
    findings: list[FindingReport] = Field(default_factory=list)
    supported_items: list[FindingReport] = Field(default_factory=list)
    rejected_hypotheses: list[RejectedHypothesisReport] = Field(default_factory=list)
    positive_security_observations: list[PositiveObservationReport] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    evidence_index: list[EvidenceIndexEntry] = Field(default_factory=list)
    source_summary: dict = Field(default_factory=dict)
    source_correlations: list[dict] = Field(default_factory=list)
    dependency_vulnerabilities: list[dict] = Field(default_factory=list)
    source_indications: list[dict] = Field(default_factory=list)
    secret_indications: list[dict] = Field(default_factory=list)
    activity_summary: dict = Field(default_factory=dict)
