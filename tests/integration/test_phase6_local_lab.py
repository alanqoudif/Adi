"""Actual loopback auth/LDAP services. Auth provider is explicitly a protocol fixture."""
import base64
import json
import shutil
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from adi.knowledge.workspace import Workspace
from adi.runtime.process import ExecutionResult, ExecutionRuntime, utcnow
from adi.runtime.shell import LocalRuntime
from adi.scope.engine import ScopeEngine
from adi.scope.models import Permissions, Scope
from adi.scope.models import TestAccount as ScopedAccount
from adi.tools.executor import ToolExecutionError, ToolExecutor
from adi.tools.registry import ToolRegistry

ROOT = Path(__file__).resolve().parents[2]


class AuthHandler(BaseHTTPRequestHandler):
    requests = 0
    lockout = False

    def do_GET(self):
        type(self).requests += 1
        credential = base64.b64decode(self.headers.get('Authorization', 'Basic ')[6:]).decode()
        self.send_response(423 if type(self).lockout else 200 if credential == 'lab-user:local-test-only' else 401)
        self.end_headers()
        self.wfile.write(b'account locked' if type(self).lockout else b'local test')

    def log_message(self, *_args):
        pass


class LocalAuthFixtureRuntime(ExecutionRuntime):
    """Emulates Hydra's output, sends exactly ONE real loopback HTTP auth request."""
    def __init__(self, url):
        self.url = url

    async def is_available(self):
        return True

    async def execute(self, argv, *, timeout=300, cwd=None, env=None):
        started = utcnow()
        account, candidate = argv[argv.index('-l')+1], argv[argv.index('-p')+1]
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.get(self.url, auth=(account, candidate))
        text = ('account locked' if response.status_code == 423 else
                f'[http-get] login: {account} password: {candidate}' if response.status_code == 200 else '')
        return ExecutionResult(command_id='local-auth-fixture', tool_name='hydra-fixture', argv=argv,
                               started_at=started, completed_at=utcnow(), exit_code=0,
                               stdout=text)


@pytest.mark.parametrize('locked', [False, True])
async def test_real_loopback_auth_service_stops_and_redacts(tmp_path, locked):
    AuthHandler.requests, AuthHandler.lockout = 0, locked
    server = ThreadingHTTPServer(('127.0.0.1', 0), AuthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        candidates = tmp_path/'operator.json'
        candidates.write_text(json.dumps([{'account':'lab-user','candidate':'local-test-only'}]))
        scope = Scope(name='auth-loopback-fixture', targets=['127.0.0.1'],
                      permissions=Permissions(authentication_testing=True),
                      test_accounts=[ScopedAccount(name='lab', username='lab-user')],
                      credential_candidate_sources={'local':str(candidates)})
        ws = Workspace.create(tmp_path/'state.db', scope)
        reg = ToolRegistry(ROOT/'skills'); reg.discover()
        reg.get('hydra').available, reg.get('hydra').binary_path = True, 'hydra-fixture'
        ex = ToolExecutor(reg, LocalAuthFixtureRuntime(f'http://127.0.0.1:{server.server_port}'),
                          ScopeEngine(scope), ws, tmp_path/'raw')
        params = {'service': 'http-get', 'port': server.server_port, 'account_scope': ['lab-user'],
                      'candidate_source_reference': 'local', 'max_attempts': 1, 'max_attempts_per_account': 1,
                      'rate_limit': 1/6, 'timeout': 5, 'stop_on_success': True,
                      'lockout_acknowledged': True, 'test_context': 'explicit loopback fixture'}
        result = await ex.run('hydra', '127.0.0.1', params)
        assert AuthHandler.requests == 1
        if locked:
            assert any(o.value.get('failure') == 'LOCKOUT_SIGNAL' for o in result)
        else:
            assert any(o.value.get('success') for o in result)
        with pytest.raises(ToolExecutionError):
            await ex.run('hydra', '127.0.0.1', params)
        assert AuthHandler.requests == 1
        for file in tmp_path.rglob('*'):
            if file.is_file() and file != candidates:
                assert b'local-test-only' not in file.read_bytes()
    finally:
        server.shutdown(); server.server_close()


def tlv(tag, value):
    length = bytes([len(value)]) if len(value) < 128 else b'\x81'+bytes([len(value)])
    return bytes([tag])+length+value


class LDAPFixture(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        for _ in range(2):
            header = self.request.recv(2)
            if not header:
                break
            size = header[1]
            if size & 128:
                size = int.from_bytes(self.request.recv(size & 127), 'big')
            data = b''
            while len(data) < size:
                data += self.request.recv(size-len(data))
            id_length = data[1]
            mid = data[2:2+id_length]
            message_id = tlv(2, mid)
            operation = data[2+id_length]
            success = tlv(10,b'\x00')+tlv(4,b'')+tlv(4,b'')
            if operation == 0x60:
                self.request.sendall(tlv(0x30,message_id+tlv(0x61,success)))
            elif operation == 0x63:
                attrs = b''
                for key, value in [(b'namingContexts',b'dc=lab,dc=local'),(b'supportedLDAPVersion',b'3')]:
                    attrs += tlv(0x30,tlv(4,key)+tlv(0x31,tlv(4,value)))
                entry = tlv(0x64,tlv(4,b'')+tlv(0x30,attrs))
                self.request.sendall(tlv(0x30,message_id+entry)+tlv(0x30,message_id+tlv(0x65,success)))


async def test_installed_ldapsearch_against_real_local_rootdse_fixture(tmp_path):
    if not shutil.which('ldapsearch'):
        pytest.skip('ldapsearch unavailable')
    server = socketserver.ThreadingTCPServer(('127.0.0.1',0), LDAPFixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        scope = Scope(name='ldap-loopback',targets=['127.0.0.1'])
        ws = Workspace.create(tmp_path/'state.db',scope)
        reg = ToolRegistry(ROOT/'skills');reg.discover()
        ex = ToolExecutor(reg,LocalRuntime(),ScopeEngine(scope),ws,tmp_path/'raw')
        result = await ex.run_capability('inspect_ldap','127.0.0.1',{'port':server.server_address[1]})
        assert any(o.type.value == 'directory_naming_context' and o.value['name']=='dc=lab,dc=local' for o in result)
        assert ws.list_actions()[0].status == 'completed'
    finally:
        server.shutdown();server.server_close()
