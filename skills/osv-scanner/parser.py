import json

from adi.source.parsers import parse_osv


def parse(stdout: str, stderr: str = '', context: dict | None = None):
    return parse_osv(json.loads(stdout))
