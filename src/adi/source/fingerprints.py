"""Fingerprint operator files and ignore rules, including uncommitted changes."""
from pathlib import Path

from adi.source.discovery import DiscoveryLimits, discover


def fingerprint(root: Path, limits: DiscoveryLimits | None = None, previous_files=None) -> str:
    return discover(root, limits or DiscoveryLimits(), previous_files=previous_files)[2]
