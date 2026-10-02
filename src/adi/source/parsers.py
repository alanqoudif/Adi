"""Normalize scanner JSON; tool alerts NEVER carry confirmation evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath

from adi.source.models import (
    DependencyVulnerability,
    SecretStatus,
    SourceFindingIndication,
    SourceLocation,
    SourceSecretIndication,
)
from adi.source.secrets import redact_code


def _location(path, start, end=None):
    # Scanner paths are references, never commands or paths to read.
    return SourceLocation(file=str(PurePosixPath(path)), start_line=max(1, int(start or 1)),
                          end_line=max(1, int(end or start or 1)))


def parse_semgrep(data):
    return [SourceFindingIndication(rule=r['check_id'], severity_source='semgrep:' + r.get('extra', {}).get('severity', 'UNKNOWN'),
        message=redact_code(r.get('extra', {}).get('message', '')),
        location=_location(r['path'], r['start']['line'], r['end']['line']),
        metadata={'metadata': sanitize(r.get('extra', {}).get('metadata', {}))}, source_tool='semgrep')
        for r in data.get('results', [])]


def sanitize(value):
    if isinstance(value, str):
        return redact_code(value)
    if isinstance(value, dict):
        return {k: '<redacted>' if k.lower() in ('secret', 'match', 'password', 'token', 'lines') else sanitize(v)
                for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    return value


def parse_gitleaks(data):
    results = []
    for r in data:
        value = r.get('Secret', '')
        # --redact supplies no raw value: use a stable tool indication fingerprint,
        # not pretend the hash represents the original secret.
        basis = value if value and value not in ('REDACTED', '<redacted>') and set(value) != {'*'} else r.get('Fingerprint', f"{r['File']}:{r['StartLine']}:{r['RuleID']}")
        results.append(SourceSecretIndication(type=r['RuleID'], file=r['File'], line=r['StartLine'],
            fingerprint=hashlib.sha256(basis.encode()).hexdigest(), confidence=0.95,
            source_tool='gitleaks', status=SecretStatus.INDICATED))
    return results


def parse_trivy(data):
    results = []
    for target in data.get('Results', []):
        for v in target.get('Vulnerabilities', []):
            results.append(DependencyVulnerability(package=v['PkgName'], installed_version=v['InstalledVersion'],
                ecosystem={'pip': 'PyPI', 'python-pkg': 'PyPI', 'node-pkg': 'npm', 'gomod': 'Go', 'jar': 'Maven', 'gemspec': 'RubyGems', 'composer': 'Packagist'}.get(target.get('Type', ''), target.get('Type', '')), advisory_id=v['VulnerabilityID'],
                fixed_version=v.get('FixedVersion', ''), severity_source='trivy:' + v.get('Severity', 'UNKNOWN'),
                source_manifest=target.get('Target', ''), evidence=['trivy local database result']))
    return results


def parse_trivy_config(data):
    return [SourceFindingIndication(rule=m['ID'], severity_source='trivy:' + m.get('Severity', 'UNKNOWN'),
        message=redact_code(m.get('Message', '')), source_tool='trivy',
        location=_location(target.get('Target', ''), m.get('CauseMetadata', {}).get('StartLine', 1),
                           m.get('CauseMetadata', {}).get('EndLine', 1)))
        for target in data.get('Results', []) for m in target.get('Misconfigurations', [])]


def parse_osv(data):
    results = []
    for source in data.get('results', []):
        for entry in source.get('packages', []):
            pkg = entry.get('package', {})
            for v in entry.get('vulnerabilities', []):
                ranges, fixes = [], []
                for affected in v.get('affected', []):
                    if affected.get('package', {}).get('name', pkg.get('name')) != pkg.get('name'):
                        continue
                    for r in affected.get('ranges', []):
                        ranges.append(json.dumps(r))
                        fixes.extend(e['fixed'] for e in r.get('events', []) if 'fixed' in e)
                results.append(DependencyVulnerability(package=pkg['name'], installed_version=pkg['version'],
                    ecosystem=pkg.get('ecosystem', ''), advisory_id=v['id'], aliases=v.get('aliases', []),
                    affected_range='; '.join(ranges), fixed_version=', '.join(fixes),
                    severity_source='osv:' + json.dumps(v.get('severity', [])),
                    source_manifest=source.get('source', {}).get('path', ''),
                    evidence=['OSV local advisory match']))
    return results


def deduplicate_vulnerabilities(items):
    result = []
    for item in items:
        ids = {item.advisory_id, *item.aliases}
        existing = next((v for v in result if v.package == item.package
                         and v.installed_version == item.installed_version and v.ecosystem == item.ecosystem
                         and ({v.advisory_id, *v.aliases} & ids)), None)
        if existing:
            existing.evidence = list(dict.fromkeys(existing.evidence + item.evidence))
            existing.aliases = sorted(set(existing.aliases) | ids - {existing.advisory_id})
            existing.fixed_version = existing.fixed_version or item.fixed_version
        else:
            result.append(item)
    return result
