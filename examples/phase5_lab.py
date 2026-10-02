"""Loopback-only fixture harness; never starts a public service."""
from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

FIXTURE = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures' / 'phase5_app'


class Phase5Lab:
    def __enter__(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
        self.base_url = f'http://127.0.0.1:{port}'
        self.process = subprocess.Popen(
            [sys.executable, '-m', 'uvicorn', 'app:app', '--host', '127.0.0.1',
             '--port', str(port), '--log-level', 'error'], cwd=FIXTURE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError('Phase 5 local fixture failed to start')
            try:
                if httpx.get(self.base_url, timeout=0.2, trust_env=False).status_code == 200:
                    return self
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        self.__exit__(None, None, None)
        raise RuntimeError('local fixture startup timeout')

    def __exit__(self, *args):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
