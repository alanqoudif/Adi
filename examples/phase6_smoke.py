"""Phase 6 acceptance: real loopback services; fixture-only providers are labelled."""
from __future__ import annotations

import asyncio
import json
import ssl
import struct
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from adi.actions import ActionType, PlannedAction
from adi.agent.context_builder import ContextBuilder
from adi.agent.orchestrator import Orchestrator
from adi.config.settings import load_config
from adi.knowledge.workspace import Workspace
from adi.runtime.shell import LocalRuntime
from adi.scope.engine import ScopeEngine
from adi.scope.models import Scope
from adi.tools.executor import ToolExecutor
from adi.tools.registry import ToolRegistry

ROOT = Path(__file__).resolve().parents[1]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path in {"/", "/health", "/admin", "/login"} else 404)
        self.end_headers()
        self.wfile.write((f'<html><a href="/admin">Local authorized phase6 lab {self.path}</a></html>').encode())

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass  # Expected from local service fingerprint probes.

    def log_message(self, *_args):
        pass


class StatePlanner:
    """Deterministic acceptance driver; chooses capabilities from observed gaps, never binaries."""
    def __init__(self, ws, http_port, tls_port, wordlist):
        self.ws, self.http_port, self.tls_port, self.wordlist = ws, http_port, tls_port, wordlist

    async def plan(self, context):
        observations = self.ws.list_observations()
        completed = {a.capability for a in self.ws.list_actions()}
        if not self.ws.list_services():
            cap, target, params = 'enumerate_services', '127.0.0.1', {'ports': f'{self.http_port},{self.tls_port}'}
        elif any(s.port == self.tls_port for s in self.ws.list_services()) and not any(o.type == 'tls_observation' for o in observations):
            cap, target, params = 'inspect_tls', '127.0.0.1', {'port': self.tls_port}
        elif any(s.port == self.http_port for s in self.ws.list_services()) and 'discover_web_content' not in completed:
            cap, target, params = 'discover_web_content', f'http://127.0.0.1:{self.http_port}', {'wordlist': str(self.wordlist), 'depth': 1}
        elif 'audit_credentials' not in completed:
            cap, target, params = 'audit_credentials', '127.0.0.1', {}
        else:
            return PlannedAction(action_type=ActionType.COMPLETE, reason_summary='Local metadata questions answered; disabled auth recorded')
        return PlannedAction(action_type=ActionType.RUN_TOOL, capability=cap, target=target,
                             parameters=params, reason_summary=f'Resolve unobserved {cap} in the local authorized lab')


def pcap_fixture(path):
    """One UDP header-only loopback flow, no payload."""
    ethernet = b'\x00'*12 + b'\x08\x00'
    ip = b'\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x11\x00\x00' + b'\x7f\x00\x00\x01'*2
    udp = struct.pack('!HHHH', 12345, 53, 8, 0)
    packet = ethernet + ip + udp
    path.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) +
                     struct.pack('<IIII', 1, 0, len(packet), len(packet)) + packet)


async def run(directory):
    directory.mkdir(parents=True, exist_ok=True)
    registry = ToolRegistry(ROOT/'skills'); registry.discover()
    for required in ('nmap', 'openssl', 'feroxbuster'):
        if not registry.get(required).available:
            raise RuntimeError(f'required live demo tool unavailable: {required}')
    http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    runtime = LocalRuntime()
    with tempfile.TemporaryDirectory(prefix='adi-tls-lab-') as temporary:
        cert, key = Path(temporary)/'cert.pem', Path(temporary)/'key.pem'
        # Local fixture generation only; no security action or remote target.
        await asyncio.to_thread(subprocess.run, [registry.get('openssl').binary_path, 'req', '-x509', '-newkey', 'rsa:2048',
                        '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'],
                       check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
        tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
        for server in (http, tls):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            capture = directory/'authorized.pcap'; pcap_fixture(capture)
            scope = Scope(name='phase6-live-loopback', targets=['127.0.0.1'], max_actions=12,
                          authorized_capture_files=[str(capture)])
            ws = Workspace.create(directory/'state.db', scope)
            ex = ToolExecutor(registry, runtime, ScopeEngine(scope), ws, directory/'raw')
            # Demonstrate unavailable preferred provider with a REAL alternate provider.
            registry.get('ffuf').available = False
            registry.get('ffuf').metadata.execution.priority = 1
            planner = StatePlanner(ws, http.server_port, tls.server_port,
                                   ROOT/'tests/fixtures/wordlists/tiny.txt')
            orchestrator = Orchestrator(ws, ex, planner, ContextBuilder(ws, scope, registry, goal="Discover and inspect local HTTP/TLS metadata within scope"))
            outcomes = await orchestrator.run(max_iterations=8)
            if registry.get('tcpdump').available:
                await ex.run('tcpdump', '127.0.0.1', {'capture_file': str(capture), 'packet_count': 1},
                             capability='inspect_pcap', reason_summary='Inspect authorized generated header-only capture')
            report = {'assessment_id': ws.assessment_id,
                'planner': 'deterministic state-based fixture; not a real LLM',
                'real_model': 'configured' if __import__('os').environ.get(load_config().provider.api_key_env) else 'unavailable: provider not configured',
                'outcomes': [o.model_dump(mode='json') for o in outcomes],
                'services': [{'port': s.port, 'name': s.name} for s in ws.list_services()],
                'evidence': [json.loads(e.metadata_json) for e in ws.list_evidence()],
                'observations': [{'type': o.type, 'source': o.source, 'value': json.loads(o.value_json)} for o in ws.list_observations()],
                'availability': {t.metadata.name: {'available':t.available,'version':t.version,'runtime':t.runtime} for t in registry.all()}}
            assert any(o.type == 'tls_observation' for o in ws.list_observations())
            assert ws.list_endpoints(), 'content discovery must enrich the real web graph'
            assert any(a.status == 'blocked' and a.capability == 'audit_credentials' for a in ws.list_actions())
            assert any(a.tool == 'feroxbuster' and a.status == 'completed' for a in ws.list_actions())
            (directory/'acceptance.json').write_text(json.dumps(report, indent=2))
            print(json.dumps({'assessment_id':ws.assessment_id,'directory':str(directory),
                              'services':report['services'],'outcomes':[o.status for o in outcomes],
                              'tool_evidence_count':len(report['evidence']), 'real_model':report['real_model']}, indent=2))
        finally:
            for server in (http, tls):
                server.shutdown(); server.server_close()


if __name__ == '__main__':
    import sys
    asyncio.run(run(Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'.adi/phase6-acceptance'))
