"""Local-only source scanners: bounded staging, no telemetry, no raw output on disk."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from pathlib import Path

from adi.evidence.models import EvidenceType
from adi.source.parsers import (
    deduplicate_vulnerabilities,
    parse_gitleaks,
    parse_osv,
    parse_semgrep,
    parse_trivy,
    parse_trivy_config,
)
from adi.source.repository import SourceWorkspace
from adi.tools.loader import load_adapter

PARSERS = {'semgrep': parse_semgrep, 'gitleaks': parse_gitleaks,
           'trivy': parse_trivy, 'osv-scanner': parse_osv}


async def _run_bounded(argv, timeout, cwd):
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'SYSTEMROOT')}
    import certifi
    env.update({'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0',
                'DO_NOT_TRACK': '1',
                'SEMGREP_LOG_FILE': str(Path(cwd) / 'semgrep.log'),
                'SEMGREP_SETTINGS_FILE': str(Path(cwd) / 'semgrep-settings.yml'),
                'SSL_CERT_FILE': certifi.where()})
    if Path(argv[0]).name in ('semgrep', 'gitleaks'):
        env['HOME'] = cwd
    process = await asyncio.create_subprocess_exec(*argv, cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    async def drain(stream):
        output = bytearray()
        while chunk := await stream.read(65536):
            output.extend(chunk)
            if len(output) > 10_000_000:
                raise ValueError('scanner output limit exceeded')
        return bytes(output)
    try:
        stdout, _stderr = await asyncio.wait_for(asyncio.gather(drain(process.stdout), drain(process.stderr)), timeout)
        await process.wait()
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    # stderr may contain source/credentials: never return/persist it.
    return process.returncode, stdout.decode('utf-8', errors='replace')


class SourceScanner:
    def __init__(self, workspace, registry):
        self.source = SourceWorkspace(workspace)
        self.registry = registry

    async def scan(self, capability, tool_name=None):
        snapshot = self.source.require_current()
        if not self.source.workspace.load_scope().permissions.source_analysis:
            raise PermissionError('source analysis disabled by scope')
        candidates = [self.registry.get(tool_name)] if tool_name else sorted(
            self.registry.available_by_capability(capability),
            key=lambda t: (t.metadata.execution.priority, t.metadata.name))
        errors = []
        for tool in candidates:
            if not tool or not tool.available or tool.metadata.name not in PARSERS:
                continue
            name = tool.metadata.name
            cache_key = name + ':' + snapshot.repository.fingerprint
            if cache_key in snapshot.scan_cache:
                return snapshot.scan_cache[cache_key]
            try:
                with tempfile.TemporaryDirectory(prefix='adi-source-') as directory:
                    stage = Path(directory) / 'repository'
                    stage.mkdir()
                    root = Path(snapshot.repository.root_path)
                    for f in snapshot.files:
                        if not f.indexed:
                            continue
                        path = root / f.path
                        if path.is_symlink() or not path.resolve().is_relative_to(root):
                            raise ValueError('source path changed')
                        with path.open('rb') as stream:
                            raw = stream.read(snapshot.repository.limits['max_file_size'] + 1)
                        if hashlib.sha256(raw).hexdigest() != f.hash:
                            raise ValueError('repository changed during scanner staging')
                        destination = stage / f.path
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(raw)
                        destination.chmod(0o600)
                    adapter = load_adapter(tool.metadata.skill_dir)
                    # Fixed argv, no planner-provided command flags or remote rule packs.
                    report_path = Path(directory) / 'redacted-gitleaks.json'
                    argv = adapter.build_argv(str(stage), {'report_path': str(report_path)}, tool.binary_path)
                    code, output = await _run_bounded(argv, tool.metadata.execution.timeout_seconds, directory)
                    if name == 'gitleaks' and report_path.exists():
                        output = report_path.read_text()
                    if code not in (0, 1) or not output.strip():
                        raise ValueError('scanner failed or produced no JSON')
                    data = json.loads(output)
                    parsed = PARSERS[name](data)
                    for item in parsed:
                        if hasattr(item, 'location'):
                            item.location.file = item.location.file.removeprefix(str(stage) + '/')
                        if hasattr(item, 'file'):
                            item.file = item.file.removeprefix(str(stage) + '/')
                        if hasattr(item, 'source_manifest'):
                            item.source_manifest = item.source_manifest.removeprefix(str(stage) + '/')
                    if name == 'trivy':
                        self._indications(snapshot, parse_trivy_config(data))
                    if name == 'gitleaks':
                        snapshot.secrets.extend(s for s in parsed if not any(
                            x.file == s.file and x.line == s.line for x in snapshot.secrets))
                        for item in parsed:
                            self.source.store.create(EvidenceType.SECRET_INDICATION, source=name,
                                subject=f'{item.file}:{item.line}', summary='Redacted scanner secret indication; never used',
                                metadata=item.model_dump(mode='json'))
                    elif name in ('osv-scanner', 'trivy'):
                        for item in parsed:
                            ev = self.source.store.create(EvidenceType.DEPENDENCY_RECORD, source=name,
                                subject=item.source_manifest, summary=f'Known affected dependency: {item.package} {item.installed_version} {item.advisory_id}; runtime exploitability not validated',
                                metadata=item.model_dump())
                            item.evidence.append(ev.id)
                        snapshot.vulnerabilities = deduplicate_vulnerabilities(snapshot.vulnerabilities + parsed)
                    else:
                        self._indications(snapshot, parsed)
                # Normalize staging paths back to repository-relative references.
                for item in snapshot.indications:
                    item.location.file = item.location.file.removeprefix(str(stage) + '/')
                for item in snapshot.secrets:
                    item.file = item.file.removeprefix(str(stage) + '/')
                for item in snapshot.vulnerabilities:
                    item.source_manifest = item.source_manifest.removeprefix(str(stage) + '/')
                summary = {'tool': name, 'results': len(parsed), 'status': 'completed'}
                snapshot.scan_cache[cache_key] = summary
                self.source.workspace.save_source(snapshot)
                self.source.workspace.record_action(action_type='source_action', capability=capability,
                    tool=name, target=snapshot.repository.root_path, scope_allowed=True,
                    scope_reason='operator-bound readable repository; offline staged scan',
                    status='completed')
                return summary
            except (TimeoutError, OSError, ValueError, KeyError, TypeError):
                errors.append(name + ': unavailable/failed JSON scan (raw diagnostic withheld)')
        snapshot.diagnostics.extend(errors or ['no available tool for ' + capability])
        self.source.workspace.save_source(snapshot)
        return {'status': 'unavailable', 'capability': capability, 'errors': errors}

    def _indications(self, snapshot, indications):
        for indication in indications:
            ev = self.source.store.create(EvidenceType.SAST_RESULT, source=indication.source_tool,
                subject=indication.location.display(), summary=indication.message,
                metadata=indication.model_dump())
            indication.evidence_id = ev.id
            snapshot.indications.append(indication)

    def review_indication(self, evidence_id):
        """Only reject a narrow, independently recognizable safe literal/guard case.

        Other alerts stay indicated. No source alert acquires runtime confirmation metadata.
        """
        snapshot = self.source.require_current()
        item = next(i for i in snapshot.indications if i.evidence_id == evidence_id)
        from adi.source.index import SourceIndex
        index = SourceIndex(snapshot)
        loc = item.location
        nearby = loc.model_copy(update={'start_line': max(1, loc.start_line - 5), 'end_line': loc.end_line + 5})
        code = index.retrieve_context(nearby)
        if item.rule.endswith('adi.literal-eval') and 'ast.literal_eval(' in code:
            item.status = 'rejected'
            item.runtime_relevance = 'non_exploitable_for_this_rule'
            item.review_reason = 'AST literal parser, not dynamic code execution; bounded source inspected'
        else:
            symbols = [s for s in snapshot.symbols if s.location.file == loc.file
                       and s.location.start_line <= loc.start_line <= s.location.end_line]
            reachable = any(r.handler in {s.name for s in symbols} for r in snapshot.routes)
            if symbols and not reachable and not any(s.name in other.calls for s in symbols for other in snapshot.symbols):
                item.runtime_relevance = 'reachability_not_established'
                item.review_reason = 'No route or indexed caller identified; incomplete static reachability'
        self.source.workspace.save_source(snapshot)
        return item

    def import_result(self, tool_name: str, data, *, provenance='operator_import'):
        """Import a saved JSON scan (also used for labeled offline acceptance fixtures)."""
        if tool_name not in PARSERS:
            raise ValueError('unsupported source scanner')
        snapshot = self.source.require_current()
        if not self.source.workspace.load_scope().permissions.source_analysis:
            raise PermissionError('source analysis disabled')
        parsed = PARSERS[tool_name](data)
        if tool_name == 'semgrep':
            self._indications(snapshot, parsed)
        elif tool_name == 'gitleaks':
            for item in parsed:
                existing = next((s for s in snapshot.secrets if s.file == item.file and s.line == item.line), None)
                if not existing:
                    snapshot.secrets.append(item)
                self.source.store.create(EvidenceType.SECRET_INDICATION, source=tool_name,
                    subject=f'{item.file}:{item.line}', summary='Redacted secret indication: ' + provenance,
                    metadata=item.model_dump(mode='json'))
        else:
            for item in parsed:
                ev = self.source.store.create(EvidenceType.DEPENDENCY_RECORD, source=tool_name,
                    subject=item.source_manifest,
                    summary=f'Known affected dependency ({provenance}): {item.package} {item.installed_version} {item.advisory_id}; runtime not validated',
                    metadata=item.model_dump())
                item.evidence.append(ev.id)
            snapshot.vulnerabilities = deduplicate_vulnerabilities(snapshot.vulnerabilities + parsed)
        self.source.workspace.save_source(snapshot)
        return parsed
