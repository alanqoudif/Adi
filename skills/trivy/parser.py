import json

from adi.source.parsers import parse_trivy


def parse(stdout: str, stderr: str = '', context: dict | None = None):
    return parse_trivy(json.loads(stdout))
