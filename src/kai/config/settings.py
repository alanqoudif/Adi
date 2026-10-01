"""Loading of `.kai.yaml` with environment-variable expansion."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from kai.config.models import KaiConfig

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value):
    if isinstance(value, str):
        def _sub(match: re.Match) -> str:
            return os.environ.get(match.group(1), "")

        return _ENV_PATTERN.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load_config(path: str | Path | None = None) -> KaiConfig:
    """Load `.kai.yaml` from `path`, or search upward from cwd. Falls back
    to defaults if no config file exists — KAI should never hard-fail just
    because a config file is missing."""
    candidate = Path(path) if path else _find_config()
    if candidate is None or not candidate.exists():
        return KaiConfig()
    raw = yaml.safe_load(candidate.read_text()) or {}
    raw = _expand_env(raw)
    return KaiConfig.model_validate(raw)


def _find_config() -> Path | None:
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / ".kai.yaml"
        if candidate.exists():
            return candidate
    return None


def default_workspace_root() -> Path:
    return Path.cwd() / ".kai"
