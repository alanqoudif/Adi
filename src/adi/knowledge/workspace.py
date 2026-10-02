"""The Workspace: the façade the rest of Adi uses to read and update an
assessment's persistent target knowledge.

Nothing outside this module should touch `adi.knowledge.db` directly —
that keeps the ORM an implementation detail and gives us one place that
knows how to turn an `Observation` into typed graph state.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from adi.knowledge.db import (
    ActionRecord,
    AssessmentRecord,
    CriticReviewRecord,
    EndpointRecord,
    EvidenceRecord,
    FindingRecord,
    HostRecord,
    HttpExchangeRecord,
    HypothesisRecord,
    ObservationRecord,
    ParameterRecord,
    PositiveObservationRecord,
    ServiceRecord,
    SessionRecord,
    ValidationActionRecord,
    ValidationBudgetRecord,
    make_session_factory,
    new_id,
)
from adi.knowledge.observations import Observation, ObservationType
from adi.scope.models import Scope


class Workspace:
    """Owns the SQLite-backed state for a single assessment."""

    def __init__(self, session_factory: sessionmaker[Session], assessment_id: str):
        self._session_factory = session_factory
        self.assessment_id = assessment_id

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def create(cls, db_path: Path, scope: Scope) -> Workspace:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        session_factory = make_session_factory(str(db_path))
        assessment_id = new_id("assess")
        with session_factory() as session:
            record = AssessmentRecord(
                id=assessment_id,
                name=scope.name,
                mode=scope.mode.value,
                scope_json=scope.model_dump_json(),
            )
            session.add(record)
            session.add(SessionRecord(
                id=new_id("sess"), assessment_id=assessment_id, name="anonymous",
                role="anonymous", authenticated=False,
            ))
            session.commit()
        return cls(session_factory, assessment_id)

    @classmethod
    def open(cls, db_path: Path, assessment_id: str | None = None) -> Workspace:
        session_factory = make_session_factory(str(db_path))
        with session_factory() as session:
            if assessment_id is None:
                record = session.execute(
                    select(AssessmentRecord).order_by(AssessmentRecord.created_at.desc())
                ).scalars().first()
                if record is None:
                    raise ValueError(f"no assessment found in {db_path}")
                assessment_id = record.id
            else:
                record = session.get(AssessmentRecord, assessment_id)
                if record is None:
                    raise ValueError(f"no assessment '{assessment_id}' found in {db_path}")
        return cls(session_factory, assessment_id)

    def load_scope(self) -> Scope:
        with self._session_factory() as session:
            record = session.get(AssessmentRecord, self.assessment_id)
            assert record is not None
            return Scope.model_validate_json(record.scope_json)

    def assessment_status(self) -> str:
        with self._session_factory() as session:
            return session.get(AssessmentRecord, self.assessment_id).status

    def set_assessment_status(self, status: str) -> None:
        with self._session_factory() as session:
            session.get(AssessmentRecord, self.assessment_id).status = status
            session.commit()

    def validation_limit(self, hypothesis_id: str, default: int = 8, *, persist: bool = True) -> int:
        with self._session_factory() as session:
            row = session.get(ValidationBudgetRecord, hypothesis_id)
            if row is None and not persist:
                return default
            if row is None:
                row = ValidationBudgetRecord(hypothesis_id=hypothesis_id, max_actions=default)
                session.add(row)
                session.commit()
            return row.max_actions

    # -- hosts / services ----------------------------------------------------

    def upsert_host(self, address: str, source: str, confidence: float = 1.0) -> str:
        with self._session_factory() as session:
            existing = session.execute(
                select(HostRecord).where(
                    HostRecord.assessment_id == self.assessment_id,
                    HostRecord.address == address,
                )
            ).scalar_one_or_none()
            if existing:
                return existing.id
            record = HostRecord(
                id=new_id("host"),
                assessment_id=self.assessment_id,
                address=address,
                source=source,
                confidence=confidence,
            )
            session.add(record)
            session.commit()
            return record.id

    def upsert_service(
        self,
        host_address: str,
        port: int,
        protocol: str,
        name: str = "",
        product: str = "",
        version: str = "",
        state: str = "open",
        source: str = "unknown",
        confidence: float = 1.0,
    ) -> str:
        host_id = self.upsert_host(host_address, source=source, confidence=confidence)
        with self._session_factory() as session:
            existing = session.execute(
                select(ServiceRecord).where(
                    ServiceRecord.host_id == host_id,
                    ServiceRecord.port == port,
                    ServiceRecord.protocol == protocol,
                )
            ).scalar_one_or_none()
            if existing:
                existing.name = name or existing.name
                existing.product = product or existing.product
                existing.version = version or existing.version
                existing.state = state
                session.commit()
                return existing.id
            record = ServiceRecord(
                id=new_id("svc"),
                host_id=host_id,
                port=port,
                protocol=protocol,
                name=name,
                product=product,
                version=version,
                state=state,
                source=source,
                confidence=confidence,
            )
            session.add(record)
            session.commit()
            return record.id

    def list_hosts(self) -> list[HostRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(HostRecord).where(HostRecord.assessment_id == self.assessment_id)
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    def list_services(self) -> list[ServiceRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ServiceRecord)
                .join(HostRecord)
                .where(HostRecord.assessment_id == self.assessment_id)
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    # -- endpoints / parameters ------------------------------------------------

    def upsert_endpoint(
        self,
        host_address: str,
        path: str,
        methods: list[str] | None = None,
        requires_auth: bool = False,
        technology: str = "",
        source: str = "unknown",
        confidence: float = 1.0,
    ) -> str:
        host_id = self.upsert_host(host_address, source=source, confidence=confidence)
        with self._session_factory() as session:
            existing = session.execute(
                select(EndpointRecord).where(
                    EndpointRecord.host_id == host_id, EndpointRecord.path == path,
                )
            ).scalar_one_or_none()
            if existing:
                merged_methods = sorted(set(json.loads(existing.methods_json)) | set(methods or []))
                existing.methods_json = json.dumps(merged_methods)
                existing.requires_auth = existing.requires_auth or requires_auth
                existing.technology = technology or existing.technology
                session.commit()
                return existing.id
            record = EndpointRecord(
                id=new_id("ep"),
                host_id=host_id,
                path=path,
                methods_json=json.dumps(sorted(set(methods or []))),
                requires_auth=requires_auth,
                technology=technology,
                source=source,
                confidence=confidence,
            )
            session.add(record)
            session.commit()
            return record.id

    def upsert_parameter(
        self, endpoint_id: str, name: str, location: str = "body",
        required: bool = True, source: str = "unknown", confidence: float = 1.0,
    ) -> str:
        with self._session_factory() as session:
            existing = session.execute(
                select(ParameterRecord).where(
                    ParameterRecord.endpoint_id == endpoint_id,
                    ParameterRecord.name == name,
                    ParameterRecord.location == location,
                )
            ).scalar_one_or_none()
            if existing:
                existing.required = required
                session.commit()
                return existing.id
            record = ParameterRecord(
                id=new_id("param"), endpoint_id=endpoint_id, name=name,
                location=location, required=required, source=source, confidence=confidence,
            )
            session.add(record)
            session.commit()
            return record.id

    def list_endpoints(self) -> list[EndpointRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(EndpointRecord)
                .join(HostRecord)
                .where(HostRecord.assessment_id == self.assessment_id)
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    def list_parameters(self, endpoint_id: str | None = None) -> list[ParameterRecord]:
        with self._session_factory() as session:
            stmt = select(ParameterRecord).join(EndpointRecord).join(HostRecord).where(
                HostRecord.assessment_id == self.assessment_id
            )
            if endpoint_id is not None:
                stmt = stmt.where(ParameterRecord.endpoint_id == endpoint_id)
            rows = session.execute(stmt).scalars().all()
            session.expunge_all()
            return list(rows)

    # -- sessions / identities --------------------------------------------------

    def get_or_create_session(
        self, name: str, role: str = "", test_account_name: str | None = None,
    ) -> str:
        with self._session_factory() as session:
            existing = session.execute(
                select(SessionRecord).where(
                    SessionRecord.assessment_id == self.assessment_id,
                    SessionRecord.name == name,
                )
            ).scalar_one_or_none()
            if existing:
                return existing.id
            record = SessionRecord(
                id=new_id("sess"), assessment_id=self.assessment_id, name=name,
                role=role, test_account_name=test_account_name,
            )
            session.add(record)
            session.commit()
            return record.id

    def set_session_authenticated(self, name: str, authenticated: bool) -> None:
        session_id = self.get_or_create_session(name)
        with self._session_factory() as session:
            record = session.get(SessionRecord, session_id)
            if record:
                record.authenticated = authenticated
                session.commit()

    def list_sessions(self) -> list[SessionRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(SessionRecord).where(SessionRecord.assessment_id == self.assessment_id)
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    # -- HTTP exchanges ----------------------------------------------------

    def record_http_exchange(self, **fields) -> str:
        exchange_id = new_id("http")
        with self._session_factory() as session:
            record = HttpExchangeRecord(id=exchange_id, assessment_id=self.assessment_id, **fields)
            session.add(record)
            session.commit()
        return exchange_id

    def list_http_exchanges(self) -> list[HttpExchangeRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(HttpExchangeRecord)
                .where(HttpExchangeRecord.assessment_id == self.assessment_id)
                .order_by(HttpExchangeRecord.started_at)
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    # -- observations ---------------------------------------------------------

    def record_observation(self, observation: Observation) -> str:
        """Store an observation and fold it into the typed graph state."""
        obs_id = new_id("obs")
        with self._session_factory() as session:
            record = ObservationRecord(
                id=obs_id,
                assessment_id=self.assessment_id,
                type=observation.type.value,
                subject=observation.subject,
                value_json=json.dumps(observation.value),
                source=observation.source,
                confidence=observation.confidence,
            )
            session.add(record)
            session.commit()
        self._apply_observation(observation)
        return obs_id

    def record_observations(self, observations: list[Observation]) -> list[str]:
        return [self.record_observation(o) for o in observations]

    def list_observations(self) -> list[ObservationRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ObservationRecord).where(
                    ObservationRecord.assessment_id == self.assessment_id
                )
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    def _apply_observation(self, observation: Observation) -> None:
        """Fold an observation into typed Host/Service/Endpoint/Session
        state. Deterministic, no LLM involved — see spec section 19/26."""
        if observation.type == ObservationType.HOST_UP:
            self.upsert_host(observation.subject, source=observation.source,
                              confidence=observation.confidence)
        elif observation.type in (
            ObservationType.OPEN_PORT,
            ObservationType.SERVICE_BANNER,
            ObservationType.SERVICE_VERSION,
        ):
            host = observation.value.get("host", observation.subject)
            self.upsert_service(
                host_address=host,
                port=observation.value.get("port", 0),
                protocol=observation.value.get("protocol", "tcp"),
                name=observation.value.get("service", ""),
                product=observation.value.get("product", ""),
                version=observation.value.get("version", ""),
                state=observation.value.get("state", "open"),
                source=observation.source,
                confidence=observation.confidence,
            )
        elif observation.type == ObservationType.WEB_ENDPOINT:
            host = observation.value.get("host", observation.subject)
            self.upsert_endpoint(
                host_address=host,
                path=observation.value.get("path", observation.subject),
                methods=observation.value.get("methods", []),
                requires_auth=observation.value.get("requires_auth", False),
                technology=observation.value.get("technology", ""),
                source=observation.source,
                confidence=observation.confidence,
            )
        elif observation.type == ObservationType.ENDPOINT_PARAMETER:
            endpoint_id = observation.value.get("endpoint_id")
            if endpoint_id:
                self.upsert_parameter(
                    endpoint_id=endpoint_id,
                    name=observation.value.get("name", observation.subject),
                    location=observation.value.get("location", "body"),
                    required=observation.value.get("required", True),
                    source=observation.source,
                    confidence=observation.confidence,
                )
        elif observation.type == ObservationType.SESSION_OBSERVED:
            self.get_or_create_session(
                name=observation.value.get("name", observation.subject),
                role=observation.value.get("role", ""),
                test_account_name=observation.value.get("test_account_name"),
            )
            if "authenticated" in observation.value:
                self.set_session_authenticated(
                    observation.value.get("name", observation.subject),
                    observation.value["authenticated"],
                )

    # -- actions (audit trail) ------------------------------------------------

    def record_action(self, **kwargs) -> str:
        from adi.reporting.redaction import known_secrets, redact_structure
        secrets = known_secrets(self.load_scope())
        if "parameters_json" in kwargs:
            kwargs["parameters_json"] = json.dumps(
                redact_structure(json.loads(kwargs["parameters_json"]), secrets))
        kwargs = redact_structure(kwargs, secrets)
        action_id = new_id("act")
        with self._session_factory() as session:
            record = ActionRecord(id=action_id, assessment_id=self.assessment_id, **kwargs)
            session.add(record)
            session.commit()
        return action_id

    def update_action_result(
        self, action_id: str, *, exit_code: int, timed_out: bool,
        stdout_path: str | None, stderr_path: str | None, status: str,
    ) -> None:
        with self._session_factory() as session:
            record = session.get(ActionRecord, action_id)
            if record:
                record.exit_code = exit_code
                record.timed_out = timed_out
                record.stdout_path = stdout_path
                record.stderr_path = stderr_path
                record.status = status
                session.commit()

    def list_actions(self) -> list[ActionRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ActionRecord).where(ActionRecord.assessment_id == self.assessment_id)
                .order_by(ActionRecord.created_at)
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    # -- hypotheses / findings (used from Phase 2 onward) ----------------------

    def upsert_hypothesis(self, hypothesis_id: str | None, **fields) -> str:
        with self._session_factory() as session:
            if hypothesis_id:
                record = session.get(HypothesisRecord, hypothesis_id)
            else:
                record = None
            if record is None:
                record = HypothesisRecord(
                    id=hypothesis_id or new_id("hyp"),
                    assessment_id=self.assessment_id,
                )
                session.add(record)
            for key, value in fields.items():
                setattr(record, key, value)
            session.commit()
            return record.id

    def list_hypotheses(self) -> list[HypothesisRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(HypothesisRecord).where(
                    HypothesisRecord.assessment_id == self.assessment_id
                )
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    def _check_confirmed_record(self, record) -> None:
        if record.status != "confirmed":
            return
        evidence_ids = json.loads(record.evidence_ids_json or "[]")
        hypotheses = {h.id for h in self.list_hypotheses()}
        if record.hypothesis_id not in hypotheses or not evidence_ids:
            raise ValueError("confirmed finding requires a hypothesis and evidence")
        if not all(self.get_evidence(eid) is not None for eid in evidence_ids):
            raise ValueError("confirmed finding has missing evidence")
        validations = self.list_validation_actions(record.hypothesis_id)
        if not any(v.scope_allowed and v.outcome == "supports"
                   and set(json.loads(v.evidence_ids_json)) & set(evidence_ids) for v in validations):
            raise ValueError("confirmed finding requires scope-authorized supporting validation")
        if record.critic_review_id:
            review = self.get_critic_review(record.critic_review_id)
            if review is None or review.hypothesis_id != record.hypothesis_id or review.decision != "accept":
                raise ValueError("confirmed finding requires an accepted linked critic review")

    def create_finding(self, **fields) -> str:
        finding_id = new_id("find")
        with self._session_factory() as session:
            record = FindingRecord(id=finding_id, assessment_id=self.assessment_id, **fields)
            self._check_confirmed_record(record)
            session.add(record)
            session.commit()
        return finding_id

    def list_findings(self) -> list[FindingRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(FindingRecord).where(FindingRecord.assessment_id == self.assessment_id)
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    def get_finding(self, finding_id: str) -> FindingRecord | None:
        with self._session_factory() as session:
            record = session.get(FindingRecord, finding_id)
            if record is not None:
                session.expunge(record)
            return record

    def update_finding(self, finding_id: str, **fields) -> None:
        with self._session_factory() as session:
            record = session.get(FindingRecord, finding_id)
            if record is None:
                raise ValueError(f"no finding '{finding_id}'")
            for key, value in fields.items():
                setattr(record, key, value)
            self._check_confirmed_record(record)
            session.commit()

    # -- evidence (Phase 4) -----------------------------------------------------

    def record_evidence(self, **fields) -> str:
        evidence_id = new_id("ev")
        with self._session_factory() as session:
            record = EvidenceRecord(id=evidence_id, assessment_id=self.assessment_id, **fields)
            session.add(record)
            session.commit()
        return evidence_id

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        with self._session_factory() as session:
            record = session.get(EvidenceRecord, evidence_id)
            if record is not None:
                session.expunge(record)
            return record

    def link_evidence_to_finding(self, evidence_id: str, finding_id: str) -> None:
        with self._session_factory() as session:
            record = session.get(EvidenceRecord, evidence_id)
            if record is None:
                raise ValueError(f"no evidence '{evidence_id}'")
            linked = json.loads(record.related_finding_ids_json)
            if finding_id not in linked:
                linked.append(finding_id)
            record.related_finding_ids_json = json.dumps(linked)
            session.commit()

    def attach_evidence_exchanges(self, evidence_id: str, exchange_ids: list[str]) -> None:
        with self._session_factory() as session:
            row = session.get(EvidenceRecord, evidence_id)
            metadata = json.loads(row.metadata_json)
            metadata["http_exchange_ids"] = exchange_ids
            row.metadata_json = json.dumps(metadata)
            row.raw_reference = ", ".join(exchange_ids) or row.raw_reference
            session.commit()

    def list_evidence(self) -> list[EvidenceRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(EvidenceRecord).where(EvidenceRecord.assessment_id == self.assessment_id)
                .order_by(EvidenceRecord.created_at)
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    # -- validation actions (Phase 4) --------------------------------------------

    def record_validation_action(self, **fields) -> str:
        action_id = new_id("val")
        with self._session_factory() as session:
            record = ValidationActionRecord(id=action_id, assessment_id=self.assessment_id, **fields)
            session.add(record)
            session.commit()
        return action_id

    def list_validation_actions(self, hypothesis_id: str | None = None) -> list[ValidationActionRecord]:
        with self._session_factory() as session:
            stmt = select(ValidationActionRecord).where(
                ValidationActionRecord.assessment_id == self.assessment_id
            )
            if hypothesis_id is not None:
                stmt = stmt.where(ValidationActionRecord.hypothesis_id == hypothesis_id)
            rows = session.execute(stmt.order_by(ValidationActionRecord.created_at)).scalars().all()
            session.expunge_all()
            return list(rows)

    # -- positive security observations (Phase 4) ---------------------------------

    def record_positive_observation(self, **fields) -> str:
        obs_id = new_id("pos")
        with self._session_factory() as session:
            session.add(PositiveObservationRecord(
                id=obs_id, assessment_id=self.assessment_id, **fields))
            session.commit()
        return obs_id

    def list_positive_observations(self) -> list[PositiveObservationRecord]:
        with self._session_factory() as session:
            rows = session.execute(
                select(PositiveObservationRecord).where(
                    PositiveObservationRecord.assessment_id == self.assessment_id)
                .order_by(PositiveObservationRecord.created_at)
            ).scalars().all()
            session.expunge_all()
            return list(rows)

    # -- critic reviews (Phase 4) -------------------------------------------------

    def record_critic_review(self, **fields) -> str:
        review_id = new_id("crit")
        with self._session_factory() as session:
            record = CriticReviewRecord(id=review_id, assessment_id=self.assessment_id, **fields)
            session.add(record)
            session.commit()
        return review_id

    def get_critic_review(self, review_id: str) -> CriticReviewRecord | None:
        with self._session_factory() as session:
            record = session.get(CriticReviewRecord, review_id)
            if record is not None:
                session.expunge(record)
            return record

    def list_critic_reviews(self, hypothesis_id: str | None = None) -> list[CriticReviewRecord]:
        with self._session_factory() as session:
            stmt = select(CriticReviewRecord).where(
                CriticReviewRecord.assessment_id == self.assessment_id
            )
            if hypothesis_id is not None:
                stmt = stmt.where(CriticReviewRecord.hypothesis_id == hypothesis_id)
            rows = session.execute(stmt.order_by(CriticReviewRecord.created_at)).scalars().all()
            session.expunge_all()
            return list(rows)
