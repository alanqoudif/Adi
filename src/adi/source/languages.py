"""Extendable language detectors; detection does not imply semantic support."""
from pathlib import Path

LANGUAGES = {
    '.py': 'Python', '.js': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript',
    '.jsx': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript', '.go': 'Go',
    '.java': 'Java', '.php': 'PHP', '.rb': 'Ruby', '.cs': 'C#', '.sh': 'Shell',
    '.bash': 'Shell', '.yaml': 'YAML', '.yml': 'YAML', '.json': 'JSON',
    '.tf': 'Terraform', '.hcl': 'Terraform', '.toml': 'TOML', '.xml': 'XML',
}


def detect_language(path: str) -> str:
    return LANGUAGES.get(Path(path).suffix.lower(), '')
