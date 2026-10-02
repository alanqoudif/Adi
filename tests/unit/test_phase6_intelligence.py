"""Mandatory Phase 6 gates; all target execution is simulated or local-only."""
import json
from pathlib import Path

import pytest

from adi.actions import ActionType, PlannedAction
from adi.knowledge.workspace import Workspace
from adi.runtime.mock import MockRuntime
from adi.scope.engine import ScopeEngine
from adi.scope.models import Permissions, Scope, TestAccount
from adi.tools.authentication import CredentialAuditRequest
from adi.tools.discovery import SkillCache, discover_local_tool
from adi.tools.executor import ScopeViolationError, ToolExecutionError, ToolExecutor
from adi.tools.intelligence import ToolFailure, classify_failure
from adi.tools.loader import load_adapter, load_parser
from adi.tools.registry import ToolRegistry

ROOT = Path(__file__).resolve().parents[2]
NEW = ['rustscan', 'openssl', 'smbclient', 'enum4linux-ng', 'ldapsearch', 'tcpdump', 'tshark',
       'hydra', 'medusa', 'dig', 'host', 'nslookup', 'ssh-keyscan']


def make(tmp_path, scope=None):
    scope = scope or Scope(name='phase6', targets=['127.0.0.1'])
    ws = Workspace.create(tmp_path/'state.db', scope)
    registry = ToolRegistry(ROOT/'skills')
    registry.discover()
    runtime = MockRuntime()
    executor = ToolExecutor(registry, runtime, ScopeEngine(scope), ws, tmp_path/'raw')
    return executor, runtime, ws


@pytest.mark.parametrize('name', NEW)
def test_new_parser_sanitized_fixture(name):
    skill = ROOT/'skills'/name
    result = load_parser(skill).parse((skill/'fixtures/result.txt').read_text(), '',
                                     {'target': '127.0.0.1', 'exit_code': 0})
    assert result
    assert 'fixture-only' not in json.dumps([o.model_dump(mode='json') for o in result])


@pytest.mark.parametrize('signal,expected', [
    ('account locked', ToolFailure.LOCKOUT_SIGNAL),
    ('429 too many requests', ToolFailure.RATE_LIMITED),
    ('unrecognized option --json', ToolFailure.UNSUPPORTED_VERSION),
    ('Permission denied', ToolFailure.PERMISSION_DENIED),
    ('connection refused', ToolFailure.CONNECTION_REFUSED),
    ('NXDOMAIN', ToolFailure.DNS_FAILURE)])
def test_classifier(signal, expected):
    assert classify_failure(signal, 1) == expected


async def test_version_recovery_fallback_evidence_and_resume(tmp_path):
    ex, runtime, ws = make(tmp_path)
    for name in ['feroxbuster', 'ffuf']:
        tool = ex.registry.get(name)
        tool.available, tool.binary_path, tool.version = True, name, 'test-version'
    runtime.script(['feroxbuster'], stderr='unknown option --json', exit_code=1)
    runtime.script(['ffuf'], stdout=(ROOT/'tests/fixtures/ffuf/scan.json').read_text())
    parameters = {'wordlist': str(ROOT/'tests/fixtures/wordlists/tiny.txt')}
    observations = await ex.run_capability('discover_web_content', 'http://127.0.0.1', parameters)
    assert observations and [c[0] for c in runtime.calls] == ['feroxbuster', 'ffuf']
    assert ex.memory.get(ex.registry.get('feroxbuster')).disabled
    from adi.tools.intelligence import PerformanceMemory
    ex.registry.memory = PerformanceMemory(tmp_path/'tool-performance.json')
    assert ex.registry.resolve('discover_web_content').metadata.name == 'ffuf'
    assert len(ws.list_evidence()) == 2
    evidence = json.loads(ws.list_evidence()[-1].metadata_json)
    assert evidence['version'] == 'test-version' and evidence['parsed_observation_ids']
    assert evidence['action_id'] in {a.id for a in ws.list_actions()}


async def test_unavailable_preferred_fallback(tmp_path):
    ex, runtime, _ws = make(tmp_path)
    ex.registry.get('feroxbuster').available = False
    ex.registry.get('ffuf').available = True
    ex.registry.get('ffuf').binary_path = 'ffuf'
    runtime.script(['ffuf'], stdout=(ROOT/'tests/fixtures/ffuf/scan.json').read_text())
    result = await ex.run_capability('discover_web_content', 'http://127.0.0.1',
        {'wordlist': str(ROOT/'tests/fixtures/wordlists/tiny.txt')})
    assert result and len(runtime.calls) == 1 and runtime.calls[0][0] == 'ffuf'


def auth_setup(tmp_path, permission=True):
    candidates = tmp_path/'operator-candidates.json'
    candidates.write_text(json.dumps([{'account': 'lab-user', 'candidate': 'tiny-secret'}]))
    scope = Scope(name='auth', targets=['127.0.0.1'],
        permissions=Permissions(authentication_testing=permission),
        test_accounts=[TestAccount(name='lab', username='lab-user')],
        credential_candidate_sources={'lab-data': str(candidates)})
    ex, runtime, ws = make(tmp_path, scope)
    for name in ('hydra', 'medusa'):
        tool = ex.registry.get(name)
        tool.available, tool.binary_path = True, name
    params = {'service': 'ssh', 'port': 2222, 'account_scope': ['lab-user'],
                  'candidate_source_reference': 'lab-data', 'max_attempts': 1,
                  'max_attempts_per_account': 1, 'rate_limit': 1/6, 'timeout': 5,
                  'stop_on_success': True, 'lockout_acknowledged': True, 'test_context': 'isolated local lab'}
    return ex, runtime, ws, params


async def test_auth_policy_blocked_before_runtime(tmp_path):
    ex, runtime, ws, params = auth_setup(tmp_path, False)
    with pytest.raises(ScopeViolationError):
        await ex.run_capability('audit_credentials', '127.0.0.1', params)
    assert runtime.calls == [] and ws.list_actions()[0].status == 'blocked'
    with pytest.raises(ScopeViolationError):
        await ex.run('hydra', '127.0.0.1', params, capability='audit_credentials')


async def test_bounded_authorized_auth_redaction_and_resume(tmp_path):
    ex, runtime, _ws, params = auth_setup(tmp_path)
    runtime.script(['hydra'], stdout='[22][ssh] host: 127.0.0.1 login: lab-user password: tiny-secret')
    result = await ex.run_capability('audit_credentials', '127.0.0.1', params)
    assert result[0].value['success'] is True
    assert len(runtime.calls) == 1
    for file in tmp_path.rglob('*'):
        if file.is_file() and file.name != 'operator-candidates.json':
            assert b'tiny-secret' not in file.read_bytes(), file
    with pytest.raises(ToolExecutionError):
        await ex.run_capability('audit_credentials', '127.0.0.1', params)
    assert len(runtime.calls) == 1


async def test_lockout_signal_stops_all_providers(tmp_path):
    ex, runtime, _ws, params = auth_setup(tmp_path)
    runtime.script(['hydra'], stdout='account locked due to lockout', exit_code=1)
    result = await ex.run_capability('audit_credentials', '127.0.0.1', params)
    assert any(o.value.get('failure') == 'LOCKOUT_SIGNAL' for o in result)
    with pytest.raises(ToolExecutionError):
        await ex.run('medusa', '127.0.0.1', params)
    assert len(runtime.calls) == 1


def test_auth_rejects_unbounded_and_unknown_fields():
    with pytest.raises(ValueError):
        CredentialAuditRequest(target='127.0.0.1', service='ssh', port=22,
            account_scope=['a'], candidate_source_reference='r', max_attempts=0,
            lockout_acknowledged=True, test_context='local lab')


async def test_smb_canonical_graph_and_provenance(tmp_path):
    ex, runtime, ws = make(tmp_path)
    nmap = '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports></host></nmaprun>'
    for name, text in [('nmap', nmap), ('enum4linux-ng', (ROOT/'skills/enum4linux-ng/fixtures/result.txt').read_text()),
                       ('smbclient', (ROOT/'skills/smbclient/fixtures/result.txt').read_text())]:
        tool = ex.registry.get(name)
        tool.available, tool.binary_path = True, name
        runtime.script([name], stdout=text)
        await ex.run(name, '127.0.0.1')
    assert len(ws.list_services()) == 1
    shares = ws.normalized_entities('smb_share')
    public = next(s for s in shares if s['value']['name'] == 'public')
    assert set(public['sources']) == {'smbclient', 'enum4linux-ng'}
    assert len(ws.list_evidence()) == 3


async def test_constrained_dynamic_help(tmp_path, monkeypatch):
    executable = tmp_path/'adi-safe-fake'
    executable.write_text('#!/bin/sh\necho "local read-only metadata helper"\n')
    executable.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path))
    from adi.runtime.shell import LocalRuntime
    scope_engine = ScopeEngine(Scope(name='local'))
    temporary = await discover_local_tool('adi-safe-fake', permitted_names=['adi-safe-fake'],
                                         runtime=LocalRuntime(), scope_engine=scope_engine)
    assert temporary.trust_level.value == 'TEMPORARY_INFERRED'
    assert temporary.inferred_capabilities == ['inspect_local_tool_help']
    with pytest.raises(ValueError):
        await discover_local_tool('other', permitted_names=[], runtime=LocalRuntime(), scope_engine=scope_engine)


def test_skill_cache_invalidates_path_version_and_content():
    registry = ToolRegistry(ROOT/'skills'); registry.discover()
    cache = SkillCache(); tool = registry.get('openssl')
    cache.relevant(tool); tool.version = 'new'; cache.relevant(tool)
    assert len(cache.entries) == 1


def test_capture_requires_explicit_scope_and_bounds():
    engine = ScopeEngine(Scope(name='capture', targets=['127.0.0.1']))
    action = PlannedAction(action_type=ActionType.RUN_TOOL, capability='capture_network_metadata',
                           target='127.0.0.1', parameters={'interface': 'en0', 'duration': 10, 'packet_count': 10})
    assert not engine.authorize(action).allowed


def test_adapter_rejects_target_option_and_ports():
    adapter = load_adapter(ROOT/'skills/rustscan')
    for target in ['--help', '127.0.0.1,example.org', '127.0.0.0/8']:
        with pytest.raises(ValueError):
            adapter.build_argv(target, {}, 'rustscan')
    with pytest.raises(ValueError):
        adapter.build_argv('127.0.0.1', {'ports': '80 --script all'}, 'rustscan')


async def test_medusa_selected_when_hydra_unavailable(tmp_path):
    ex, runtime, _ws, params = auth_setup(tmp_path)
    ex.registry.get('hydra').available = False
    runtime.script(['medusa'], stdout='ACCOUNT FOUND: [ssh] User: lab-user Password: tiny-secret [SUCCESS]')
    result = await ex.run_capability('audit_credentials', '127.0.0.1', params)
    assert result[0].value['success']
    assert runtime.calls[0][0] == 'medusa'


def test_permission_and_approval_cannot_be_disguised():
    scope = Scope(name='approval',targets=['127.0.0.1'],approval_mode=True,
                  permissions=Permissions(authentication_testing=True))
    engine = ScopeEngine(scope)
    action = PlannedAction(action_type=ActionType.RUN_TOOL,capability='audit_credentials',target='127.0.0.1')
    assert not engine.authorize(action).allowed
    scope.approved_elevated_actions = ['audit_credentials:127.0.0.1']
    assert engine.authorize(action).allowed
    scope.permissions.authentication_testing = False
    assert not engine.authorize(action).allowed


async def test_auth_tool_cannot_disguise_capability(tmp_path):
    ex,runtime,_ws,params = auth_setup(tmp_path,False)
    with pytest.raises(ToolExecutionError):
        await ex.run('hydra','127.0.0.1',params,capability='inspect_dns')
    assert not runtime.calls


async def test_parser_failure_keeps_redacted_raw_and_disables_provider(tmp_path):
    ex,runtime,ws = make(tmp_path)
    tool = ex.registry.get('nmap'); tool.available,tool.binary_path = True,'nmap'
    runtime.script(['nmap'],stdout='not XML password=hidden-value')
    result = await ex.run('nmap','127.0.0.1')
    assert result[0].value['failure'] == 'PARSER_FAILURE'
    assert ex.memory.get(tool).disabled
    evidence = ws.list_evidence()[0]
    assert Path(evidence.raw_reference).exists()
    assert 'hidden-value' not in Path(evidence.raw_reference).read_text()


async def test_partial_timeout_preserves_valid_observations(tmp_path):
    ex,runtime,ws = make(tmp_path)
    tool = ex.registry.get('rustscan');tool.available,tool.binary_path = True,'rustscan'
    runtime.script(['rustscan'],stdout='127.0.0.1 -> [80]',timed_out=True,exit_code=-1)
    await ex.run('rustscan','127.0.0.1')
    evidence = json.loads(ws.list_evidence()[0].metadata_json)
    assert len(ws.list_services()) == 1
    assert evidence['failure']=='PARTIAL_SUCCESS' and evidence['failure_cause']=='TIMEOUT'


def test_custom_plugin_validation_never_imports_code(tmp_path):
    import yaml

    from adi.tools.plugins import validate_plugin
    (tmp_path/'tool.yaml').write_text(yaml.safe_dump({'name':'local','capabilities':['inspect_dns'],
                                                   'execution':{'binary':'local'}}))
    for file in ('adapter.py','parser.py'):
        (tmp_path/file).write_text('raise RuntimeError("must never execute during validation")')
    (tmp_path/'SKILL.md').write_text('pending operator review')
    assert validate_plugin(tmp_path).trust_level.value == 'LOCAL_DISCOVERED'
    (tmp_path/'parser.py').unlink()
    with pytest.raises(ValueError):
        validate_plugin(tmp_path)


def test_installed_unknown_version_remains_available(tmp_path):
    from adi.tools.registry import RegisteredTool, ToolMetadata
    tool = RegisteredTool(metadata=ToolMetadata(name='fake',capabilities=['inspect_dns']),
                          available=True,binary_path=str(tmp_path/'fake'))
    assert ToolRegistry.probe_version(tool)=='unknown' and tool.available


async def test_container_inventory_does_not_inherit_host_paths():
    from adi.runtime.docker_runtime import DockerKaliRuntime
    class MissingDocker(DockerKaliRuntime):
        async def is_available(self):
            return False
    reg=ToolRegistry(ROOT/'skills');reg.discover()
    reg.get('nmap').available=True
    await reg.detect_runtime(MissingDocker())
    assert not reg.get('nmap').available and reg.get('nmap').runtime=='docker-kali'
    assert reg.get('nmap').availability_by_runtime['docker-kali']['available'] is False


async def test_invalid_auth_limits_and_references_never_execute(tmp_path):
    ex,runtime,_ws,params=auth_setup(tmp_path)
    for bad in ({'max_attempts':0}, {'rate_limit':100}, {'lockout_acknowledged':False},
                {'candidate_source_reference':'discovered-secret'}, {'account_scope':['outside']},
                {'shell':'anything'}):
        with pytest.raises(ToolExecutionError):
            await ex.run('hydra','127.0.0.1',{**params,**bad})
    assert not runtime.calls


async def test_account_budget_survives_resume_without_success(tmp_path):
    ex,runtime,_ws,params=auth_setup(tmp_path)
    runtime.script(['hydra'],stdout='')
    await ex.run('hydra','127.0.0.1',params)
    assert len(runtime.calls)==1
    new_ex,_,_=make(tmp_path/'resume',ex.scope_engine.scope)
    new_ex.raw_output_dir=tmp_path/'raw'
    new_ex.registry.get('hydra').available,new_ex.registry.get('hydra').binary_path=True,'hydra'
    new_ex.runtime=runtime
    await new_ex.run('hydra','127.0.0.1',params)
    assert len(runtime.calls)==1


async def test_auth_global_elevated_budget_limits_candidate_loop(tmp_path):
    ex,runtime,_ws,params=auth_setup(tmp_path)
    ex.scope_engine.scope.max_elevated_actions=1
    candidates=Path(ex.scope_engine.scope.credential_candidate_sources['lab-data'])
    candidates.write_text(json.dumps([{'account':'lab-user','candidate':'tiny-secret'},
                                     {'account':'lab-user','candidate':'tiny-secret-2'}]))
    params.update(max_attempts=2,max_attempts_per_account=2)
    # The second attempt will be reserved but never executed once the assessment budget stops it.
    runtime.script(['hydra'],stdout='')
    params['rate_limit']=1/6
    import adi.tools.authentication as auth
    async def no_wait(_delay):
        pass
    from unittest.mock import patch
    with patch.object(auth.asyncio,'sleep',no_wait), pytest.raises(ToolExecutionError):
        await ex.run('hydra','127.0.0.1',params)
    assert len(runtime.calls)==1


def test_smb_error_cannot_create_a_service():
    parser=load_parser(ROOT/'skills/smbclient')
    with pytest.raises(ValueError):
        parser.parse('NT_STATUS_LOGON_FAILURE','',{'target':'127.0.0.1','exit_code':0})
