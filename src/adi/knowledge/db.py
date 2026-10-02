"""SQLAlchemy persistence layer for an assessment workspace.

This is the canonical, durable state. A NetworkX graph (see `adi.knowledge.graph`)
is derived from it on demand for relationship queries — it is not the source
of truth, so nothing is lost if the graph is rebuilt.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Base(DeclarativeBase):
    pass


class AssessmentRecord(Base):
    __tablename__ = "assessment"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    mode: Mapped[str] = mapped_column(String)
    scope_json: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    hosts: Mapped[list[HostRecord]] = relationship(back_populates="assessment")
    observations: Mapped[list[ObservationRecord]] = relationship(back_populates="assessment")
    actions: Mapped[list[ActionRecord]] = relationship(back_populates="assessment")
    hypotheses: Mapped[list[HypothesisRecord]] = relationship(back_populates="assessment")
    findings: Mapped[list[FindingRecord]] = relationship(back_populates="assessment")
    sessions: Mapped[list[SessionRecord]] = relationship(back_populates="assessment")
    http_exchanges: Mapped[list[HttpExchangeRecord]] = relationship(back_populates="assessment")
    evidence_items: Mapped[list[EvidenceRecord]] = relationship(back_populates="assessment")
    validation_actions: Mapped[list[ValidationActionRecord]] = relationship(back_populates="assessment")
    critic_reviews: Mapped[list[CriticReviewRecord]] = relationship(back_populates="assessment")
    positive_observations: Mapped[list[PositiveObservationRecord]] = relationship(
        back_populates="assessment"
    )


class HostRecord(Base):
    __tablename__ = "host"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    address: Mapped[str] = mapped_column(String)  # IP or hostname
    hostnames_json: Mapped[str] = mapped_column(Text, default="[]")
    source: Mapped[str] = mapped_column(String, default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="hosts")
    services: Mapped[list[ServiceRecord]] = relationship(back_populates="host")
    endpoints: Mapped[list[EndpointRecord]] = relationship(back_populates="host")


class ServiceRecord(Base):
    __tablename__ = "service"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("host.id"))
    port: Mapped[int] = mapped_column()
    protocol: Mapped[str] = mapped_column(String, default="tcp")
    name: Mapped[str] = mapped_column(String, default="")  # e.g. http, ssh
    product: Mapped[str] = mapped_column(String, default="")
    version: Mapped[str] = mapped_column(String, default="")
    state: Mapped[str] = mapped_column(String, default="open")
    source: Mapped[str] = mapped_column(String, default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    host: Mapped[HostRecord] = relationship(back_populates="services")


class ObservationRecord(Base):
    __tablename__ = "observation"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    type: Mapped[str] = mapped_column(String)
    subject: Mapped[str] = mapped_column(String)
    value_json: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="observations")

    @property
    def value(self):
        return json.loads(self.value_json)


class EndpointRecord(Base):
    """A web application route: a path plus the HTTP methods observed on
    it, whether it appears to require authentication, and (optionally) the
    technology serving it. Parameters live in `ParameterRecord`, one row
    per (endpoint, parameter)."""

    __tablename__ = "endpoint"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("host.id"))
    path: Mapped[str] = mapped_column(String)  # e.g. "/api/orders"
    methods_json: Mapped[str] = mapped_column(Text, default="[]")  # e.g. ["GET", "POST"]
    requires_auth: Mapped[bool] = mapped_column(Boolean, default=False)
    technology: Mapped[str] = mapped_column(String, default="")
    source: Mapped[str] = mapped_column(String, default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    host: Mapped[HostRecord] = relationship(back_populates="endpoints")
    parameters: Mapped[list[ParameterRecord]] = relationship(back_populates="endpoint")


class ParameterRecord(Base):
    __tablename__ = "parameter"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoint.id"))
    name: Mapped[str] = mapped_column(String)
    location: Mapped[str] = mapped_column(String, default="body")  # body | query | path | header
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String, default="unknown")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    endpoint: Mapped[EndpointRecord] = relationship(back_populates="parameters")


class SessionRecord(Base):
    """A named identity the agent tests with — "anonymous" always exists by
    default; others correspond to `Scope.test_accounts` entries. This is
    deliberately NOT the full HTTP cookie/request-response workspace (that
    is Phase 3) — only which identities exist and whether each is currently
    authenticated."""

    __tablename__ = "session"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    name: Mapped[str] = mapped_column(String)  # e.g. "anonymous", "user_a", "admin"
    role: Mapped[str] = mapped_column(String, default="")
    authenticated: Mapped[bool] = mapped_column(Boolean, default=False)
    test_account_name: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="sessions")


class HttpExchangeRecord(Base):
    """A persisted HTTP request/response pair. Headers are already redacted
    by the time they reach this record — see `adi.http.redaction`."""

    __tablename__ = "http_exchange"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    method: Mapped[str] = mapped_column(String)
    url: Mapped[str] = mapped_column(String)
    session_id: Mapped[str] = mapped_column(String, default="anonymous")
    status: Mapped[int | None] = mapped_column(nullable=True)
    content_type: Mapped[str] = mapped_column(String, default="")
    content_length: Mapped[int] = mapped_column(default=0)
    body_hash: Mapped[str] = mapped_column(String, default="")
    title: Mapped[str | None] = mapped_column(String, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String, default="http_client")
    evidence_path: Mapped[str | None] = mapped_column(String, nullable=True)
    redirects_json: Mapped[str] = mapped_column(Text, default="[]")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="http_exchanges")


class ActionRecord(Base):
    """An audit-log entry for every action the orchestrator attempted."""

    __tablename__ = "action"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    action_type: Mapped[str] = mapped_column(String)
    capability: Mapped[str] = mapped_column(String, default="")
    tool: Mapped[str] = mapped_column(String, default="")
    target: Mapped[str] = mapped_column(String, default="")
    parameters_json: Mapped[str] = mapped_column(Text, default="{}")
    reason_summary: Mapped[str] = mapped_column(Text, default="")
    scope_allowed: Mapped[bool] = mapped_column(default=True)
    scope_reason: Mapped[str] = mapped_column(Text, default="")
    exit_code: Mapped[int | None] = mapped_column(nullable=True)
    timed_out: Mapped[bool] = mapped_column(default=False)
    stdout_path: Mapped[str | None] = mapped_column(String, nullable=True)
    stderr_path: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="planned")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="actions")


class HypothesisRecord(Base):
    __tablename__ = "hypothesis"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    title: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String, default="")
    status: Mapped[str] = mapped_column(String, default="new")
    confidence: Mapped[float] = mapped_column(Float, default=0.3)
    supporting_observation_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    contradicting_observation_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    validation_plan_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="hypotheses")


class EvidenceRecord(Base):
    """A first-class evidence item (spec Phase 4 section 2). Raw content
    may live on disk (`raw_reference`); only a bounded, redacted
    `sanitized_preview` ever reaches planner/critic context."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    type: Mapped[str] = mapped_column(String)  # EvidenceType value
    source: Mapped[str] = mapped_column(String, default="")
    subject: Mapped[str] = mapped_column(String, default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    raw_reference: Mapped[str | None] = mapped_column(String, nullable=True)
    sanitized_preview: Mapped[str] = mapped_column(Text, default="")
    hash: Mapped[str] = mapped_column(String, default="")
    related_hypothesis_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    related_finding_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="evidence_items")


class ValidationActionRecord(Base):
    """An audit-log entry for every validation action executed — distinct
    from `ActionRecord` (the orchestrator's tool/HTTP action log) so a
    hypothesis's validation history can be queried on its own (spec
    section 45)."""

    __tablename__ = "validation_action"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("hypothesis.id"))
    action_type: Mapped[str] = mapped_column(String)  # ValidationActionType value
    session_id: Mapped[str] = mapped_column(String, default="")
    parameters_json: Mapped[str] = mapped_column(Text, default="{}")
    outcome: Mapped[str] = mapped_column(String, default="")  # ValidationOutcome value
    scope_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    reason_summary: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="validation_actions")


class ValidationBudgetRecord(Base):
    __tablename__ = "validation_budget"
    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("hypothesis.id"), primary_key=True)
    max_actions: Mapped[int] = mapped_column(default=8)


class PositiveObservationRecord(Base):
    """A security control that behaved correctly (spec Phase 4 section 6).
    Deliberately separate from findings — secure behavior never becomes a
    Finding."""

    __tablename__ = "positive_observation"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    category: Mapped[str] = mapped_column(String, default="")
    title: Mapped[str] = mapped_column(String)
    summary: Mapped[str] = mapped_column(Text, default="")
    asset: Mapped[str] = mapped_column(String, default="")
    endpoint: Mapped[str] = mapped_column(String, default="")
    session: Mapped[str] = mapped_column(String, default="")
    evidence_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="positive_observations")


class CriticReviewRecord(Base):
    __tablename__ = "critic_review"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    hypothesis_id: Mapped[str] = mapped_column(ForeignKey("hypothesis.id"))
    decision: Mapped[str] = mapped_column(String)  # CriticDecision value
    concerns_json: Mapped[str] = mapped_column(Text, default="[]")
    additional_validation_needed_json: Mapped[str] = mapped_column(Text, default="[]")
    confidence_adjustment: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="critic_reviews")


class FindingRecord(Base):
    __tablename__ = "finding"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessment.id"))
    hypothesis_id: Mapped[str | None] = mapped_column(ForeignKey("hypothesis.id"), nullable=True)
    critic_review_id: Mapped[str | None] = mapped_column(
        ForeignKey("critic_review.id"), nullable=True
    )
    title: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String, default="")
    severity: Mapped[str] = mapped_column(String, default="info")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String, default="indicated")
    summary: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    evidence_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    affected_assets_json: Mapped[str] = mapped_column(Text, default="[]")
    affected_endpoints_json: Mapped[str] = mapped_column(Text, default="[]")
    affected_roles_json: Mapped[str] = mapped_column(Text, default="[]")
    validation_summary: Mapped[str] = mapped_column(Text, default="")
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    assessment: Mapped[AssessmentRecord] = relationship(back_populates="findings")


def create_engine_for(db_path: str):
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    Base.metadata.create_all(engine)
    # Additive checkpoint compatibility; never invent authorization for old rows.
    columns = {c["name"] for c in inspect(engine).get_columns("validation_action")}
    with engine.begin() as conn:
        if "scope_allowed" not in columns:
            conn.execute(text("ALTER TABLE validation_action ADD COLUMN scope_allowed BOOLEAN DEFAULT 0"))
    return engine


def make_session_factory(db_path: str) -> sessionmaker[Session]:
    engine = create_engine_for(db_path)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)
