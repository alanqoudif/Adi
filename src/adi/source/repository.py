"""Index lifecycle and source evidence, tied to one operator-selected root."""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from adi.agent.reasoner import HypothesisEngine
from adi.evidence.models import EvidenceType
from adi.evidence.store import EvidenceStore
from adi.knowledge.hypotheses import HypothesisStatus
from adi.source import auth
from adi.source.correlation import correlate
from adi.source.dependencies import detect_frameworks, parse_dependencies
from adi.source.discovery import DiscoveryLimits, discover
from adi.source.fingerprints import fingerprint
from adi.source.models import Repository, RootCause, SourceHypothesisIndication, SourceSnapshot
from adi.source.routes import discover_routes


class SourceWorkspace:
    def __init__(self, workspace):
        self.workspace = workspace
        self.store = EvidenceStore(workspace)

    def load(self, check_stale=True):
        snapshot = self.workspace.load_source()
        if snapshot and check_stale and not snapshot.repository.stale:
            try:
                current = fingerprint(Path(snapshot.repository.root_path), DiscoveryLimits(**snapshot.repository.limits), snapshot.files)
                snapshot.repository.stale = current != snapshot.repository.fingerprint
            except (OSError, ValueError):
                snapshot.repository.stale = True
            if snapshot.repository.stale:
                snapshot.correlations = []
                self.workspace.save_source(snapshot)
        return snapshot

    def require_current(self):
        snapshot = self.load()
        if not snapshot or snapshot.repository.stale:
            raise ValueError('source index missing or stale; operator must index repository')
        return snapshot

    def assert_hypothesis_current(self, hypothesis_id):
        source_evidence = [e for e in self.workspace.list_evidence()
                           if e.type == 'source_snippet' and hypothesis_id in json.loads(e.related_hypothesis_ids_json)]
        if not source_evidence:
            return
        snapshot = self.require_current()
        for evidence in source_evidence:
            digest = json.loads(evidence.metadata_json).get('fingerprint')
            if digest and digest != snapshot.repository.fingerprint:
                raise ValueError('source hypothesis is from an older repository fingerprint')

    def index(self, root: Path, application_origin: str = '', limits=None):
        if not self.workspace.load_scope().permissions.source_analysis:
            raise PermissionError('source analysis disabled by scope')
        root = root.resolve(strict=True)
        previous = self.workspace.load_source()
        # A planner cannot switch the operator-selected repository.
        if previous and Path(previous.repository.root_path) != root:
            raise PermissionError('repository already bound; create a new assessment to change it')
        limits = limits or DiscoveryLimits()
        if (previous and previous.repository.limits == asdict(limits)
                and fingerprint(root, limits, previous.files) == previous.repository.fingerprint):
            previous.repository.stale = False
            if application_origin:
                url = urlsplit(application_origin)
                if not self.workspace.load_scope().host_is_target(url.hostname or ''):
                    raise PermissionError('application origin outside configured scope')
                origin = url._replace(path='', query='', fragment='').geturl().rstrip('/')
                if origin != previous.repository.application_origin:
                    previous.repository.application_origin = origin
                    previous.correlations = []
            self.workspace.save_source(previous)
            return previous
        files, secrets, digest, diagnostics = discover(root, limits)
        if application_origin:
            url = urlsplit(application_origin)
            if not self.workspace.load_scope().host_is_target(url.hostname or ''):
                raise PermissionError('application origin outside configured scope')
            application_origin = url._replace(path='', query='', fragment='').geturl().rstrip('/')
        if previous and previous.repository.fingerprint == digest and previous.repository.limits == asdict(limits):
            if application_origin and application_origin != previous.repository.application_origin:
                previous.repository.application_origin = application_origin
                previous.correlations = []
            previous.repository.stale = False
            self.workspace.save_source(previous)
            return previous
        dependencies, dependency_errors = parse_dependencies(files)
        repository = Repository(id='repo-' + hashlib.sha256(str(root).encode()).hexdigest()[:16],
            root_path=str(root), fingerprint=digest, languages=sorted({f.language for f in files if f.indexed and f.language}),
            frameworks=detect_frameworks(files, dependencies), files_count=sum(f.indexed for f in files),
            package_managers=sorted({d.ecosystem for d in dependencies}),
            application_origin=application_origin or (previous.repository.application_origin if previous else ''),
            limits=asdict(limits))
        for flag, field in [('--show-toplevel', None), ('HEAD', 'commit_hash'), ('--abbrev-ref', 'branch')]:
            if field is None:
                continue
            argv = ['git', '-C', str(root), 'rev-parse', flag]
            if field == 'branch':
                argv.append('HEAD')
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=3, check=False)
                if result.returncode == 0:
                    setattr(repository, field, result.stdout.strip())
            except (OSError, subprocess.TimeoutExpired):
                pass
        routes, symbols = discover_routes(files)
        snapshot = SourceSnapshot(repository=repository, files=files, secrets=secrets,
            dependencies=dependencies, routes=routes, symbols=symbols,
            diagnostics=diagnostics + dependency_errors)
        auth.analyze(snapshot)
        self._hypotheses(snapshot)
        for secret in secrets:
            self.store.create(EvidenceType.SECRET_INDICATION, source=secret.source_tool,
                subject=f'{secret.file}:{secret.line}', summary=f'{secret.type}: confirmed presence; test-only={secret.test_only}',
                metadata=secret.model_dump(mode='json'))
        for config in snapshot.configs:
            self.store.create(EvidenceType.SOURCE_CONFIG, source='source', subject=config.location.display(),
                summary=f'{config.kind} ({config.environment})', raw_text=config.behavior,
                metadata=config.model_dump())
        self.workspace.save_source(snapshot)
        return snapshot

    def _hypotheses(self, snapshot):
        engine = HypothesisEngine(self.workspace)
        for route in snapshot.routes:
            controls, flow, slices = auth.inspect_route(snapshot, route)
            # Restrict IDOR candidates to read routes with object-shaped path parameters.
            if route.method != 'GET' or '{' not in route.path:
                continue
            observation = ('ownership guard pattern observed; verify runtime enforcement' if any(c.type == 'authorization' for c in controls)
                           else 'ownership validation not established in bounded handler/helper context')
            plan = ['observe endpoint and correlate application', 'establish two authorized test sessions',
                    'verify controlled object ownership', 'compare owner and other identity; deny expected',
                    'critic reviews helpers, middleware, reachability and protected object response']
            hyp = engine.create(f'Possible broken object authorization on {route.method} {route.path}',
                category='broken_object_authorization', validation_plan=plan)
            evidence_ids = []
            for slice in slices:
                loc = slice['location']
                ev = self.store.create(EvidenceType.SOURCE_SNIPPET, source='source',
                    subject=f"{loc['file']}:{loc['start_line']}-{loc['end_line']}",
                    summary=observation + '; ' + slice['code'][:1000], raw_text=slice['code'],
                    related_hypothesis_ids=[hyp.id], metadata={'location': loc, 'route_id': route.id,
                    'fingerprint': snapshot.repository.fingerprint})
                evidence_ids.append(ev.id)
            ev = self.store.create(EvidenceType.SOURCE_ROUTE, source='source', subject=route.path,
                summary=f'{route.method} {route.path} handler={route.handler}; middleware={route.middleware}',
                related_hypothesis_ids=[hyp.id], metadata=route.model_dump())
            evidence_ids.append(ev.id)
            engine.transition(hyp.id, HypothesisStatus.INVESTIGATING,
                              new_supporting_observation_ids=evidence_ids)
            snapshot.hypotheses.append(SourceHypothesisIndication(route_id=route.id,
                hypothesis_id=hyp.id, evidence_ids=evidence_ids, observation=observation,
                flow=flow, validation_plan=plan))

    def correlate(self):
        snapshot = self.require_current()
        snapshot.correlations = correlate(snapshot, self.workspace)
        self.workspace.save_source(snapshot)
        return snapshot.correlations

    def enrich_finding(self, finding_id):
        snapshot = self.require_current()
        finding = self.workspace.get_finding(finding_id)
        if not finding:
            raise ValueError('finding does not exist')
        if finding.status != 'confirmed' or finding.category != 'broken_object_authorization':
            return None
        endpoints = json.loads(finding.affected_endpoints_json)
        from adi.source.routes import route_matches
        routes = [r for r in snapshot.routes if any(route_matches(r.path, e) for e in endpoints)
                  and any(c.route_id == r.id for c in snapshot.correlations)]
        if not routes:
            return None
        route = routes[0]
        controls, _flow, slices = auth.inspect_route(snapshot, route)
        locations = [s['location'] for s in slices]
        guard_observed = any(c.type == 'authorization' for c in controls)
        missing = ('effective object ownership enforcement on the validated path' if guard_observed
                   else 'object ownership condition before returning the resource')
        summary = ('Ownership guard syntax is present, but did not deny cross-user access on the validated path; inspect guard semantics and reachability.' if guard_observed
                   else 'Object lookup/return is not constrained to the authenticated owner on the validated path.')
        root = RootCause(summary=summary,
            source_locations=locations, security_control_missing=missing,
            related_symbols=[route.handler, *route.middleware], confidence=0.85,
            finding_id=finding_id)
        snapshot.root_causes = [r for r in snapshot.root_causes if r.finding_id != finding_id] + [root]
        # Reverse investigation attaches source evidence to an existing runtime hypothesis.
        for s in slices:
            if not any(e.type == 'source_snippet' and e.subject == f"{s['location']['file']}:{s['location']['start_line']}-{s['location']['end_line']}"
                       and finding_id in json.loads(e.related_finding_ids_json) for e in self.workspace.list_evidence()):
                ev = self.store.create(EvidenceType.SOURCE_SNIPPET, source='source',
                    subject=f"{s['location']['file']}:{s['location']['start_line']}-{s['location']['end_line']}",
                    summary='Correlated root-cause source context', raw_text=s['code'],
                    related_hypothesis_ids=[finding.hypothesis_id] if finding.hypothesis_id else [],
                    related_finding_ids=[finding_id], metadata={'location': s['location'],
                    'fingerprint': snapshot.repository.fingerprint})
                self.workspace.update_finding(finding_id,
                    evidence_ids_json=json.dumps(json.loads(self.workspace.get_finding(finding_id).evidence_ids_json) + [ev.id]))
        self.workspace.update_finding(finding_id, remediation=f'In {route.location.file}, before {route.handler} returns the object, '
            'enforce that its owner/user_id equals the authenticated principal, or use the existing policy helper. '
            'Preserve explicit role/tenant grants and test cross-user denial.')
        self.workspace.save_source(snapshot)
        return root

    def summary(self):
        snapshot = self.load()
        if not snapshot:
            return {}
        return {'repository': snapshot.repository.model_dump(mode='json'),
                'source_files': snapshot.repository.files_count, 'routes': len(snapshot.routes),
                'dependencies': len(snapshot.dependencies), 'sast_indications': len(snapshot.indications),
                'secrets': len(snapshot.secrets), 'dependency_advisories': len(snapshot.vulnerabilities),
                'correlations': len(snapshot.correlations), 'source_hypotheses': len(snapshot.hypotheses),
                'diagnostics': snapshot.diagnostics[-10:]}
