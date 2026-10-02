"""Validate user tool contracts without importing or executing their Python code."""
from pathlib import Path

import yaml

from adi.tools.registry import ToolMetadata


def validate_plugin(directory: Path) -> ToolMetadata:
    directory = directory.resolve()
    raw = yaml.safe_load((directory/'tool.yaml').read_text())
    metadata = ToolMetadata.model_validate(raw)
    if not metadata.capabilities or not (metadata.execution.binary or metadata.binary_names):
        raise ValueError('plugin must declare capabilities and executable')
    if metadata.risk_level not in {'passive', 'low', 'moderate', 'elevated', 'prohibited'}:
        raise ValueError('invalid plugin risk')
    for name in (metadata.adapter, metadata.parser, 'SKILL.md'):
        path = directory/name
        if Path(name).name != name or not path.is_file() or path.is_symlink():
            raise ValueError('invalid or missing plugin component')
    # This validates metadata ONLY: caller still must review and explicitly install.
    metadata.skill_dir = directory
    metadata.trusted = False
    from adi.tools.intelligence import TrustLevel
    metadata.trust_level = TrustLevel.LOCAL_DISCOVERED
    return metadata
