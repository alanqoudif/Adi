"""Dynamic loading of a tool skill's adapter/parser modules.

A skill is loaded only when the planner actually selects it — tool
documentation is never dumped into the main system prompt (spec section 7).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _load_module(path: Path, qualified_name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(qualified_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified_name] = module
    spec.loader.exec_module(module)
    return module


def load_adapter(skill_dir: Path) -> ModuleType:
    return _load_module(skill_dir / "adapter.py", f"kai_skill_{skill_dir.name}_adapter")


def load_parser(skill_dir: Path) -> ModuleType:
    return _load_module(skill_dir / "parser.py", f"kai_skill_{skill_dir.name}_parser")


def load_skill_doc(skill_dir: Path) -> str:
    skill_md = skill_dir / "SKILL.md"
    return skill_md.read_text() if skill_md.exists() else ""
