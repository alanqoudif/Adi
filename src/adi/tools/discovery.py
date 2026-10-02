"""Opt-in local help discovery; inferred metadata never imports plugin code."""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from adi.actions import ActionType, PlannedAction, RiskLevel
from adi.tools.intelligence import TrustLevel


class TemporaryToolSkill(BaseModel):
    name: str
    path: str
    observed_help: str
    inferred_capabilities: list[str] = Field(default_factory=list)
    input_schema_guess: dict = Field(default_factory=dict)
    risk_guess: str = 'low'
    confidence: float = 0.2
    limitations: list[str] = Field(default_factory=lambda: [
        'Only local help inspection; target execution needs reviewed adapter and parser'])
    trust_level: TrustLevel = TrustLevel.TEMPORARY_INFERRED
    provenance: str = 'local help; inferred'


async def discover_local_tool(name, *, permitted_names, runtime, scope_engine):
    if name not in permitted_names or Path(name).name != name:
        raise ValueError('discovery requires configured executable allowlist')
    path = shutil.which(name)
    if not path:
        return None
    action = PlannedAction(action_type=ActionType.LOAD_SKILL, risk=RiskLevel.LOW,
                           capability='inspect_local_tool_help')
    if not scope_engine.authorize(action).allowed:
        raise ValueError('local help discovery blocked')
    result = await runtime.execute([path, '--help'], timeout=3)
    from adi.evidence.redaction import redact_secrets
    return TemporaryToolSkill(name=name, path=path,
        observed_help=redact_secrets(result.stdout + result.stderr)[:4000],
        inferred_capabilities=['inspect_local_tool_help'])


class SkillCache:
    def __init__(self):
        self.entries = {}

    def relevant(self, tool):
        path = tool.metadata.skill_dir / 'SKILL.md'
        content = path.read_text()
        key = (str(path), hashlib.sha256(content.encode()).hexdigest(),
               tool.binary_path, tool.version)
        if key not in self.entries:
            self.entries = {k: v for k, v in self.entries.items() if k[0] != str(path)}
            self.entries[key] = content[:6000]
        return self.entries[key]
