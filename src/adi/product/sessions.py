"""Human-readable session registry layered over `Assessment` ids.

Users should not have to memorize assessment UUIDs/ids. A `.adi/product/
sessions.json` file maps a short name (e.g. "orders-api") to the
underlying assessment id plus display metadata used by `/sessions` and
auto-resume.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from pydantic import BaseModel, Field


class SessionRecord(BaseModel):
    name: str
    assessment_id: str
    target: str = ""
    model: str = ""
    created_at: float = Field(default_factory=time.time)
    last_activity: float = Field(default_factory=time.time)


class SessionStore(BaseModel):
    sessions: dict[str, SessionRecord] = Field(default_factory=dict)


def _path(project_root: Path | None = None) -> Path:
    root = project_root or Path.cwd()
    directory = root / ".adi" / "product"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "sessions.json"


_SLUG_RE = re.compile(r"[^a-z0-9-]+")


def slugify(text: str) -> str:
    slug = _SLUG_RE.sub("-", text.lower()).strip("-")
    return slug or "session"


class SessionRegistry:
    def __init__(self, project_root: Path | None = None):
        self.project_root = project_root or Path.cwd()
        self.path = _path(self.project_root)
        self.store = self._load()

    def _load(self) -> SessionStore:
        if self.path.exists():
            try:
                return SessionStore.model_validate_json(self.path.read_text())
            except Exception:  # noqa: BLE001,S110 - corrupt/missing session store falls back to empty
                pass
        return SessionStore()

    def save(self) -> None:
        self.path.write_text(self.store.model_dump_json(indent=2))

    def register(self, assessment_id: str, target: str, model: str = "", name: str | None = None) -> SessionRecord:
        base = slugify(name or target or assessment_id)
        candidate = base
        n = 2
        while candidate in self.store.sessions and self.store.sessions[candidate].assessment_id != assessment_id:
            candidate = f"{base}-{n}"
            n += 1
        record = self.store.sessions.get(candidate) or SessionRecord(
            name=candidate, assessment_id=assessment_id, target=target, model=model
        )
        record.target = target or record.target
        record.model = model or record.model
        record.last_activity = time.time()
        self.store.sessions[candidate] = record
        self.save()
        return record

    def touch(self, name: str) -> None:
        if name in self.store.sessions:
            self.store.sessions[name].last_activity = time.time()
            self.save()

    def get(self, name: str) -> SessionRecord | None:
        return self.store.sessions.get(name)

    def list(self) -> list[SessionRecord]:
        return sorted(self.store.sessions.values(), key=lambda r: r.last_activity, reverse=True)

    def most_recent(self) -> SessionRecord | None:
        items = self.list()
        return items[0] if items else None

    def remove(self, name: str) -> None:
        self.store.sessions.pop(name, None)
        self.save()
