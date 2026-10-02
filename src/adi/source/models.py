"""Provider-independent, line-addressable source intelligence."""
from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class SourceLocation(BaseModel):
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    symbol: str = ""
    hash: str = ""

    def display(self) -> str:
        return f"{self.file}:{self.start_line}-{self.end_line}"


class SourceFile(BaseModel):
    path: str
    language: str = ""
    size: int
    mtime_ns: int = 0
    hash: str = ""
    indexed: bool = False
    skip_reason: str = ""
    content: str = ""  # ONLY redacted text; never raw secrets


class SourceSymbol(BaseModel):
    name: str
    kind: str
    location: SourceLocation
    calls: list[str] = Field(default_factory=list)


class SourceRoute(BaseModel):
    id: str
    method: str
    path: str
    handler: str
    middleware: list[str] = Field(default_factory=list)
    location: SourceLocation
    framework: str
    confidence: float = 0.9


class SourceMiddleware(BaseModel):
    name: str
    location: SourceLocation | None = None
    behavior: list[str] = Field(default_factory=list)
    inspected: bool = False


class SourceDependency(BaseModel):
    package: str
    installed_version: str
    ecosystem: str
    source_manifest: str
    direct_or_transitive: str = "unknown"
    location: SourceLocation


class SecretStatus(str, Enum):
    INDICATED = "indicated"
    CONFIRMED_PRESENT = "confirmed_present"
    FALSE_POSITIVE = "false_positive"
    IGNORED = "ignored"


class SourceSecretIndication(BaseModel):
    type: str
    file: str
    line: int
    fingerprint: str
    confidence: float = 0.8
    entropy: float | None = None
    source_tool: str
    status: SecretStatus = SecretStatus.INDICATED
    test_only: bool = False


SecretIndication = SourceSecretIndication


class SourceFindingIndication(BaseModel):
    rule: str
    severity_source: str
    message: str
    location: SourceLocation
    metadata: dict = Field(default_factory=dict)
    source_tool: str
    status: str = "indicated"
    runtime_relevance: str = "unvalidated"
    review_reason: str = ""
    evidence_id: str = ""
    hypothesis_id: str = ""


class SourceFramework(BaseModel):
    name: str
    confidence: float
    location: SourceLocation
    signal: str


class SourceConfig(BaseModel):
    kind: str
    behavior: str
    environment: str = "unknown"
    location: SourceLocation


class SourceDatabaseAccess(BaseModel):
    kind: str
    location: SourceLocation
    expression: str


class SourceAuthControl(BaseModel):
    type: str
    behavior: str
    location: SourceLocation
    confidence: float
    route_id: str = ""


class DataFlowStep(BaseModel):
    kind: str
    expression: str
    location: SourceLocation


class SourceHypothesisIndication(BaseModel):
    route_id: str
    hypothesis_id: str
    evidence_ids: list[str]
    observation: str
    flow: list[DataFlowStep] = Field(default_factory=list)
    validation_plan: list[str] = Field(default_factory=list)


class DependencyVulnerability(BaseModel):
    package: str
    installed_version: str
    ecosystem: str
    advisory_id: str
    aliases: list[str] = Field(default_factory=list)
    affected_range: str = ""
    fixed_version: str = ""
    severity_source: str
    source_manifest: str
    direct_or_transitive: str = "unknown"
    evidence: list[str] = Field(default_factory=list)
    status: str = "KNOWN_AFFECTED_DEPENDENCY"
    runtime_exploitability: str = "not_validated"


SourceDependencyVulnerability = DependencyVulnerability


class SourceRuntimeCorrelation(BaseModel):
    route_id: str
    endpoint_id: str
    method: str
    runtime_path: str
    application_origin: str
    confidence: float
    reasons: list[str]
    fingerprint: str


class RootCause(BaseModel):
    summary: str
    source_locations: list[SourceLocation]
    security_control_missing: str
    related_symbols: list[str]
    confidence: float
    finding_id: str


class Repository(BaseModel):
    id: str
    root_path: str
    languages: list[str] = Field(default_factory=list)
    frameworks: list[SourceFramework] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    files_count: int = 0
    indexed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    commit_hash: str = ""
    branch: str = ""
    fingerprint: str
    stale: bool = False
    application_origin: str = ""
    limits: dict = Field(default_factory=dict)


class SourceSnapshot(BaseModel):
    repository: Repository
    files: list[SourceFile] = Field(default_factory=list)
    symbols: list[SourceSymbol] = Field(default_factory=list)
    routes: list[SourceRoute] = Field(default_factory=list)
    middleware: list[SourceMiddleware] = Field(default_factory=list)
    dependencies: list[SourceDependency] = Field(default_factory=list)
    secrets: list[SourceSecretIndication] = Field(default_factory=list)
    indications: list[SourceFindingIndication] = Field(default_factory=list)
    configs: list[SourceConfig] = Field(default_factory=list)
    database_access: list[SourceDatabaseAccess] = Field(default_factory=list)
    auth_controls: list[SourceAuthControl] = Field(default_factory=list)
    hypotheses: list[SourceHypothesisIndication] = Field(default_factory=list)
    vulnerabilities: list[DependencyVulnerability] = Field(default_factory=list)
    correlations: list[SourceRuntimeCorrelation] = Field(default_factory=list)
    root_causes: list[RootCause] = Field(default_factory=list)
    scan_cache: dict = Field(default_factory=dict)
    diagnostics: list[str] = Field(default_factory=list)
