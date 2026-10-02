import json

from adi.source.parsers import parse_gitleaks


def parse(stdout: str, stderr: str = '', context: dict | None = None):
    return parse_gitleaks(json.loads(stdout))
