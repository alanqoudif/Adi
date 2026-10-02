import json

from adi.source.parsers import parse_semgrep


def parse(stdout: str, stderr: str = '', context: dict | None = None):
    return parse_semgrep(json.loads(stdout))
