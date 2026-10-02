"""Deterministic smbclient metadata parser."""
from adi.tools.reviewed import parse as reviewed_parse


def parse(stdout, stderr, context):
    return reviewed_parse('smbclient', stdout, stderr, context)


def parse_result(stdout, stderr, context):
    from adi.tools.intelligence import ParsedToolResult, classify_failure
    return ParsedToolResult(observations=parse(stdout, stderr, context),
        failure_classification=classify_failure(stderr, context.get('exit_code', 0)))
