from __future__ import annotations

import json
from pathlib import Path

import pytest

from adi.knowledge.workspace import Workspace
from adi.scope.models import Scope
from adi.source.dependencies import parse_dependencies
from adi.source.discovery import DiscoveryLimits, discover
from adi.source.index import SourceIndex
from adi.source.models import SourceFile
from adi.source.parsers import parse_gitleaks, parse_osv, parse_semgrep, parse_trivy
from adi.source.repository import SourceWorkspace
from adi.source.retrieval import retrieve_route_context
from adi.source.routes import discover_routes, normalize_route, route_matches
from adi.source.secrets import redact_code


@pytest.mark.parametrize(('original', 'canonical'), [('/api/orders/:id', '/api/orders/{id}'),
    ('/api/orders/<int:id>', '/api/orders/{id}'), ('/api/orders/{id:int}', '/api/orders/{id}')])
def test_normalize_routes(original, canonical):
    assert normalize_route(original) == canonical
    assert route_matches(canonical, '/api/orders/123')
    assert not route_matches(canonical, '/api/orders/123/another')


def test_discovery_ignore_caps_binary_symlinks_redaction(tmp_path):
    (tmp_path / '.gitignore').write_text('ignored/\n*.log\n')
    (tmp_path / '.adiignore').write_text('private.py\n')
    for directory in ('node_modules', 'ignored', 'nested'):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / 'sample.py').write_text('print(1)')
    (tmp_path / 'private.py').write_text('print(2)')
    (tmp_path / 'debug.log').write_text('ignored')
    (tmp_path / 'nested' / '.gitignore').write_text('sample.py\n')
    (tmp_path / 'binary.bin').write_bytes(b'a\0b')
    (tmp_path / 'huge.txt').write_bytes(b'x' * 2048)
    (tmp_path / 'app.py').write_text('API_KEY="fake-long-secret-value"\n')
    (tmp_path / 'link.py').symlink_to(tmp_path / 'app.py')
    files, secrets, _fingerprint, _diagnostics = discover(tmp_path, DiscoveryLimits(max_file_size=1024))
    paths = {f.path for f in files}
    assert 'private.py' not in paths and 'debug.log' not in paths and 'link.py' not in paths
    assert not any('sample.py' in p for p in paths)
    assert next(f for f in files if f.path == 'binary.bin').skip_reason == 'binary'
    assert next(f for f in files if f.path == 'huge.txt').skip_reason == 'max_file_size'
    assert secrets[0].fingerprint and secrets[0].status.value == 'confirmed_present'
    assert 'fake-long-secret-value' not in next(f for f in files if f.path == 'app.py').content
    files, *_ = discover(tmp_path, DiscoveryLimits(max_indexed_files=1, max_total_indexed_bytes=20))
    assert sum(f.indexed for f in files) <= 1
    assert sum(f.size for f in files if f.indexed) <= 20


def test_stale_index_and_resume_without_git(tmp_path):
    root = tmp_path / 'repository'
    root.mkdir()
    (root / 'app.py').write_text('from fastapi import FastAPI\napp = FastAPI()\n@app.get("/api/orders/{id}")\ndef handler(id: int):\n    return {}\n')
    workspace = Workspace.create(tmp_path / 'state.db', Scope(name='source'))
    source = SourceWorkspace(workspace)
    before = source.index(root)
    assert before.repository.commit_hash == ''
    resumed = SourceWorkspace(Workspace.open(tmp_path / 'state.db', workspace.assessment_id))
    assert resumed.index(root).repository.indexed_at == before.repository.indexed_at
    index = SourceIndex(before)
    assert index.find_route('/api/orders/1')
    assert index.search_symbol('handler')
    assert index.search_text('FastAPI')
    assert index.search_regex(r'def \w+')
    with pytest.raises(ValueError):
        index.search_regex('(a+)+')
    context = retrieve_route_context(before, before.routes[0], max_chars=80)
    assert sum(len(s['code']) for s in context) <= 80
    (root / 'app.py').write_text((root / 'app.py').read_text() + '\n# changed\n')
    assert resumed.load().repository.stale
    with pytest.raises(ValueError, match='stale'):
        resumed.require_current()
    refreshed = resumed.index(root)
    assert refreshed.repository.fingerprint != before.repository.fingerprint
    assert not refreshed.repository.stale
    assert refreshed.scan_cache == {} and refreshed.correlations == []


def file(path, content, language):
    return SourceFile(path=path, content=content, language=language, indexed=True, size=len(content))


def test_express_and_flask_routes_middleware_and_service_context():
    files = [file('routes.ts', '''import express from 'express';
const app = express();
app.use(requireAuth);
app.get('/api/orders/:id', requireAdmin, getOrder);
function getOrder(req, res) { return res.json(findOrder(req.params.id)); }
function requireAuth(req, res, next) { if (!req.user) return res.status(401); next(); }
function findOrder(id) { return db.orders.findById(id); }
''', 'TypeScript'), file('app.py', '''from flask import Flask
app = Flask(__name__)
@app.route('/items/<int:id>', methods=['GET', 'POST'])
def item(id):
    return str(id)
''', 'Python')]
    routes, symbols = discover_routes(files)
    express = next(r for r in routes if r.framework == 'Express')
    assert express.path == '/api/orders/{id}' and express.handler == 'getOrder'
    assert express.middleware == ['requireAuth', 'requireAdmin']
    assert {r.method for r in routes if r.framework == 'Flask'} == {'GET', 'POST'}
    assert {s.name for s in symbols} >= {'getOrder', 'findOrder', 'requireAuth', 'item'}


@pytest.mark.parametrize(('name', 'text', 'expected'), [
    ('package.json', '{"dependencies":{"express":"4.0.0"}}', 'express'),
    ('package-lock.json', '{"packages":{"":{"dependencies":{"express":"4.0.0"}},"node_modules/express":{"version":"4.0.0"}}}', 'express'),
    ('pnpm-lock.yaml', 'packages:\n  express@4.0.0: {}\n', 'express'),
    ('yarn.lock', 'express@^4:\n  version "4.0.0"\n', 'express'),
    ('requirements.txt', 'fastapi==0.100.0\n', 'fastapi'),
    ('poetry.lock', '[[package]]\nname="flask"\nversion="1.0.0"', 'flask'),
    ('pyproject.toml', '[project]\ndependencies=["flask==1.0.0"]', 'flask'),
    ('Pipfile.lock', '{"default":{"flask":{"version":"==1.0.0"}}}', 'flask'),
    ('go.mod', 'require example.org/test v1.0.0', 'example.org/test'),
    ('go.sum', 'example.org/test v1.0.0 h1:hash', 'example.org/test'),
    ('pom.xml', '<project><dependencies><dependency><groupId>org.test</groupId><artifactId>demo</artifactId><version>1.0</version></dependency></dependencies></project>', 'org.test:demo'),
    ('build.gradle', "implementation 'org.test:demo:1.0'", 'org.test:demo'),
    ('composer.json', '{"require":{"laravel/framework":"1.0"}}', 'laravel/framework'),
    ('Gemfile.lock', '    rails (1.0.0)', 'rails'),
])
def test_deterministic_manifest_parsers(name, text, expected):
    deps, errors = parse_dependencies([file(name, text, '')])
    assert not errors and deps[0].package == expected
    assert deps[0].location.start_line >= 1


def test_scanner_parsers_never_preserve_secret_values_or_confirm_runtime():
    secret = 'never-persist-this-detected-secret'
    data = [{'RuleID': 'generic-api-key', 'File': 'app.py', 'StartLine': 1, 'Secret': secret, 'Match': secret}]
    result = parse_gitleaks(data)[0]
    assert secret not in result.model_dump_json()
    assert result.status.value == 'indicated'
    root = Path(__file__).resolve().parents[2] / 'skills'
    osv = parse_osv(json.loads((root / 'osv-scanner/fixtures/result.json').read_text()))[0]
    trivy = parse_trivy(json.loads((root / 'trivy/fixtures/result.json').read_text()))[0]
    semgrep = parse_semgrep(json.loads((root / 'semgrep/fixtures/result.json').read_text()))[0]
    assert osv.runtime_exploitability == trivy.runtime_exploitability == 'not_validated'
    assert semgrep.status == 'indicated'
    code = 'DATABASE_URL="postgresql://user:db-password@localhost/db"\nAPI_TOKEN="long-fake-test-token"\n'
    cleaned = redact_code(code)
    assert 'db-password' not in cleaned and 'long-fake-test-token' not in cleaned
    assert cleaned.count('\n') == code.count('\n')


def test_source_permission_binding_and_duplicate_secret_scrub(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    secret = 'fake_duplicate_credential_string'
    (root / 'a.py').write_text(f'value = "{secret}"\n')
    (root / 'z.env').write_text(f'API_SECRET="{secret}"\n')
    ws = Workspace.create(tmp_path / 'state.db', Scope(name='bound'))
    source = SourceWorkspace(ws)
    snapshot = source.index(root)
    assert secret not in snapshot.model_dump_json()
    assert secret.encode() not in (tmp_path / 'state.db').read_bytes()
    other = tmp_path / 'other'
    other.mkdir()
    with pytest.raises(PermissionError, match='bound'):
        source.index(other)
    forbidden = Workspace.create(tmp_path / 'forbidden.db', Scope(name='no-source', permissions={'source_analysis': False}))
    with pytest.raises(PermissionError):
        SourceWorkspace(forbidden).index(root)


def test_old_source_hypothesis_cannot_be_finalized_after_refresh(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    code = 'from fastapi import FastAPI\napp=FastAPI()\n@app.get("/orders/{id}")\ndef order(id:int):\n    return {"id":id}\n'
    (root / 'app.py').write_text(code)
    ws = Workspace.create(tmp_path / 'state.db', Scope(name='fresh'))
    source = SourceWorkspace(ws)
    before = source.index(root)
    old_hypothesis = before.hypotheses[0].hypothesis_id
    (root / 'app.py').write_text(code + '\n# revision\n')
    after = source.index(root)
    assert after.hypotheses[0].hypothesis_id != old_hypothesis
    with pytest.raises(ValueError, match='older'):
        source.assert_hypothesis_current(old_hypothesis)


def test_router_level_dependencies_are_inspected_and_name_is_not_proof():
    f = file('app.py', '''from fastapi import FastAPI, APIRouter, Depends, HTTPException
router = APIRouter(prefix='/api', dependencies=[Depends(require_auth)])
@router.get('/orders/{id}')
def get_order(id: int):
    return find_order(id)
def require_auth(token):
    if not token:
        raise HTTPException(status_code=401)
    return token
''', 'Python')
    routes, symbols = discover_routes([f])
    assert routes[0].middleware == ['require_auth']
    assert any(s.name == 'require_auth' for s in symbols)


@pytest.mark.asyncio
async def test_dependency_capability_falls_back_on_tool_failure(tmp_path, monkeypatch):
    from adi.assessment import discover_skills_dir
    from adi.source.scanners import SourceScanner
    from adi.tools.registry import ToolRegistry
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'package.json').write_text('{"dependencies":{"adi-test-vulnerable-lib":"1.0.0"}}')
    ws = Workspace.create(tmp_path / 'state.db', Scope(name='fallback'))
    SourceWorkspace(ws).index(root)
    registry = ToolRegistry(discover_skills_dir())
    registry.discover()
    for name in ('osv-scanner', 'trivy'):
        registry.get(name).available = True
        registry.get(name).binary_path = name
    called = []
    async def run(argv, timeout, cwd):
        called.append(argv[0])
        if argv[0] == 'osv-scanner':
            return 2, ''
        return 0, (discover_skills_dir() / 'trivy/fixtures/result.json').read_text()
    monkeypatch.setattr('adi.source.scanners._run_bounded', run)
    result = await SourceScanner(ws, registry).scan('scan_dependencies')
    assert result['tool'] == 'trivy'
    assert called == ['osv-scanner', 'trivy']
    snapshot = SourceWorkspace(ws).require_current()
    assert len(snapshot.vulnerabilities) == 1 and snapshot.vulnerabilities[0].evidence
    assert not ws.list_findings()
