"""Explicit operator references, one candidate per invocation, persistent stop state."""
from __future__ import annotations

import asyncio
import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from adi.tools.intelligence import classify_failure, safe_target


class CredentialAuditRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str
    service: Literal['ssh', 'ftp', 'http-get']
    port: int = Field(ge=1, le=65535)
    account_scope: list[str] = Field(min_length=1, max_length=3)
    candidate_source_reference: str
    max_attempts: int = Field(default=3, ge=1, le=10)
    max_attempts_per_account: int = Field(default=2, ge=1, le=3)
    rate_limit: float = Field(default=1/6, gt=0, le=1/6)
    timeout: int = Field(default=30, ge=1, le=60)
    stop_on_success: bool = True
    lockout_acknowledged: bool
    test_context: str = Field(min_length=5, max_length=300)

    def validate_operator_data(self, scope):
        safe_target(self.target)
        if not self.lockout_acknowledged:
            raise ValueError('explicit lockout acknowledgment required')
        authorized = scope.credential_candidate_sources.get(self.candidate_source_reference)
        if not authorized:
            raise ValueError('candidate reference must be supplied by operator scope')
        accounts = {a.username for a in scope.test_accounts}
        if not set(self.account_scope) <= accounts:
            raise ValueError('account_scope must use operator test accounts')
        if self.rate_limit * 60 > scope.rate_limits.authentication_requests_per_minute:
            raise ValueError('rate exceeds scope authentication limit')
        path = Path(authorized)
        if not path.is_file() or path.stat().st_size > 16384:
            raise ValueError('candidate data missing or exceeds bound')
        data = json.loads(path.read_text())
        if not isinstance(data, list) or not 0 < len(data) <= self.max_attempts:
            raise ValueError('candidate set exceeds attempt budget')
        counts = Counter()
        for row in data:
            if set(row) != {'account', 'candidate'} or row['account'] not in self.account_scope:
                raise ValueError('candidate account outside explicit account scope')
            if not isinstance(row['candidate'], str) or not 0 < len(row['candidate']) <= 128:
                raise ValueError('invalid candidate')
            if '\n' in row['candidate'] or '\r' in row['candidate']:
                raise ValueError('multiline candidate forbidden')
            counts[row['account']] += 1
        if any(n > self.max_attempts_per_account for n in counts.values()):
            raise ValueError('per-account attempt budget exceeded')
        return data


def build_auth_argv(tool, request, account, candidate, binary):
    host = safe_target(request.target)
    if tool == 'hydra':
        return [binary, '-I', '-l', account, '-p', candidate, '-t', '1', '-f',
                '-s', str(request.port), '-w', str(request.timeout), '-W', '6',
                host, request.service]
    if tool == 'medusa' and request.service in {'ssh', 'ftp'}:
        return [binary, '-h', host, '-u', account, '-p', candidate, '-M', request.service,
                '-n', str(request.port), '-t', '1', '-T', '1', '-f']
    raise ValueError('service not supported by reviewed authentication adapter')


async def execute_audit(executor, tool, target, parameters, capability, reason):
    # Authorization has already happened before any operator data is read.
    request = CredentialAuditRequest.model_validate({**parameters, 'target': target})
    scope = executor.scope_engine.scope
    candidates = request.validate_operator_data(scope)
    from adi.reporting.redaction import redact_structure, redact_text
    candidate_secrets = tuple(row['candidate'] for row in candidates)
    parameters = redact_structure(parameters, candidate_secrets)
    reason = redact_text(reason, candidate_secrets)
    state_path = executor.raw_output_dir.parent / 'auth-state.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    key = f'{target}|{request.service}|{request.port}'
    prior = state.get(key, {'attempts': 0, 'accounts': {}, 'stopped': False, 'last_attempt': 0})
    if prior['stopped']:
        raise ValueError('credential audit stopped for this service; operator review required')
    observations = []
    import time
    for row in candidates:
        account = row['account']
        if (prior['attempts'] >= request.max_attempts or
                prior['accounts'].get(account, 0) >= request.max_attempts_per_account):
            break
        # Reserve BEFORE execution; a crash cannot reset the budget on resume.
        wait = max(0, 1 / request.rate_limit - (time.time() - prior['last_attempt']))
        if wait:
            await asyncio.sleep(wait)
        prior['attempts'] += 1
        prior['accounts'][account] = prior['accounts'].get(account, 0) + 1
        prior['last_attempt'] = time.time()
        state[key] = prior
        state_path.write_text(json.dumps(state))
        argv = build_auth_argv(tool.metadata.name, request, account, row['candidate'],
                               tool.binary_path or tool.metadata.name)
        action_id = executor._begin_action(tool, target, parameters, capability, reason)
        # Hydra restore files and provider side effects stay in ephemeral storage.
        with tempfile.TemporaryDirectory(prefix='adi-auth-') as directory:
            cwd = '/tmp' if tool.runtime == 'docker-kali' else directory
            result = await executor._execute(argv, request.timeout, cwd=cwd)
        failure = classify_failure(result.stdout + result.stderr, result.exit_code, result.timed_out)
        # Parse before redacting, then omit credential values from every persisted surface.
        parsed = executor._parse(tool, result, target)
        for obs in parsed:
            obs.value.pop('password', None)
            obs.value['candidate_reference'] = request.candidate_source_reference
            obs.value['account'] = account
        for secret in (row['candidate'], account):
            result.stdout = result.stdout.replace(secret, '<secret-ref>')
            result.stderr = result.stderr.replace(secret, '<secret-ref>')
        result.argv = ['<secret-ref>' if x in {account, row['candidate']} else x for x in argv]
        success = any(o.value.get('success') for o in parsed)
        stop = failure is not None or (success and request.stop_on_success)
        prior['stopped'] |= stop
        state_path.write_text(json.dumps(state))
        observations += executor._record_execution(tool, target, parameters, capability, reason,
                                                   result, parsed, failure, action_id=action_id)
        if stop:
            break
    return observations
