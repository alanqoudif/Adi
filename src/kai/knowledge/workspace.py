"""The Workspace: the façade the rest of KAI uses to read and update an
assessment's persistent target knowledge.

Nothing outside this module should touch `kai.knowledge.db` directly —
that keeps the ORM an implementation detail and gives us one place that
knows how to turn an `Observation` into typed graph state.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from kai.knowledge.db import (
    ActionRecord,
    AssessmentRecord,
    FindingRecord,
    HostRecord,
    HypothesisRecord,
    ObservationRecord,
    ServiceRecord,
    make_session_factory,
    new_id,
)
from kai.knowledge.observations import Observation, ObservationType
from kai.scope.models import Scope


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
        """Fold an observation into typed Host/Service state. Deterministic,
        no LLM involved — see spec section 19/26."""
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

    # -- actions (audit trail) ------------------------------------------------

    def record_action(self, **kwargs) -> str:
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

    def create_finding(self, **fields) -> str:
        finding_id = new_id("find")
        with self._session_factory() as session:
            record = FindingRecord(id=finding_id, assessment_id=self.assessment_id, **fields)
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
