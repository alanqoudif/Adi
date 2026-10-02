"""Product-facing setup uses HTTP fixtures, never paid credentials."""
import json

import httpx
import pytest
from typer.testing import CliRunner

from adi.cli import app
from adi.config.models import AdiConfig, RuntimeConfig
from adi.llm.base import LLMMessage
from adi.product import credentials
from adi.product.models import ModelManager, ProviderProfile, build_llm_provider
from adi.product.onboarding import setup_provider
from adi.product.plain_shell import PlainShell
from adi.product.tui.app import AdiApp, AdiCommands

SECRET = 'canary-private-value-987654'


@pytest.fixture(autouse=True)
def isolated_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv('ADI_CONFIG_HOME', str(tmp_path / 'keys'))
    monkeypatch.setattr(credentials, 'keyring_available', lambda: False)


@pytest.fixture
def provider_http(monkeypatch):
    requests = []
    status = [200]
    malformed = [False]

    def handle(request):
        requests.append(request)
        if status[0] != 200:
            return httpx.Response(status[0], json={'error': SECRET})
        if request.url.path.endswith('/models'):
            return httpx.Response(200, json={'data': [{'id': 'fixture-a'}, {'id': 'fixture-b'}]})
        if malformed[0]:
            return httpx.Response(200, json={'private': SECRET})
        return httpx.Response(200, json={'choices': [{'message': {'content': 'OK'}}],
                                        'content': [{'type': 'text', 'text': 'OK'}]})

    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: original(**kw, transport=httpx.MockTransport(handle)))
    return requests, status, malformed


def prompt_answers(values, seen=None):
    answers = iter(values)

    async def prompt(label, secret=False):
        if seen is not None:
            seen.append((label, secret))
        return next(answers)
    return prompt


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['openai', 'anthropic', 'openrouter', 'ollama', 'lmstudio', 'vllm', 'openai-compatible'])
async def test_setup_all_provider_kinds(tmp_path, provider_http, kind):
    manager = ModelManager(tmp_path)
    values = [kind, 'p']
    if kind in ('ollama', 'lmstudio', 'vllm', 'openai-compatible'):
        values += ['http://127.0.0.1:1234/v1']
    if kind != 'ollama':
        values += [SECRET if kind in ('openai', 'anthropic', 'openrouter') else '']
    values += ['2', 'y']
    output, prompts = [], []
    assert await setup_provider(manager, prompt_answers(values, prompts), output.append)
    active = manager.active_profile()
    assert active.kind == kind and active.model == 'fixture-b'
    assert SECRET not in manager.path.read_text()
    assert SECRET not in '\n'.join(output)
    assert all(is_secret for label, is_secret in prompts if label.startswith('API key'))
    assert 'Response received' in '\n'.join(output)
    if kind == 'openrouter':
        assert str(provider_http[0][-1].url) == 'https://openrouter.ai/api/v1/chat/completions'
    if kind == 'ollama':
        assert 'Authorization' not in provider_http[0][-1].headers


@pytest.mark.asyncio
async def test_edit_switch_model_delete_and_role_cleanup(tmp_path, provider_http):
    m = ModelManager(tmp_path)
    p = ProviderProfile(name='a', kind='openrouter', model='fixture-a')
    m.add_profile(p, secret=SECRET)
    cached = m.provider_for()
    output = []
    assert await setup_provider(m, prompt_answers(['', '2', 'y']), output.append, edit='a')
    assert m.active_profile().model == 'fixture-b'
    assert m.provider_for() is not cached
    assert credentials.get_secret('a', 'keyring') == SECRET
    m.add_profile(ProviderProfile(name='b', kind='ollama', model='fixture-a', locality='local'))
    m.set_active('b')
    m.set_model('manual-model')
    assert ModelManager(tmp_path).active_profile().model == 'manual-model'
    m.set_role('critic', 'a')
    m.remove_profile('a')
    assert credentials.get_secret('a', 'keyring') is None
    assert m.store.roles.critic is None
    m.remove_profile('b')
    assert m.active_profile() is None


@pytest.mark.asyncio
async def test_failed_auth_does_not_save_or_leak(tmp_path, provider_http):
    provider_http[1][0] = 401
    manager = ModelManager(tmp_path)
    out = []
    assert not await setup_provider(manager, prompt_answers(['openrouter', '', SECRET, 'manual', 'y']), out.append)
    assert 'Authentication rejected' in '\n'.join(out)
    assert SECRET not in '\n'.join(out)
    assert not manager.list_profiles()
    assert credentials.get_secret('openrouter', 'keyring') is None


@pytest.mark.asyncio
@pytest.mark.parametrize('status, expected', [(403, 'Authentication rejected'), (404, 'Model not found'), (429, 'quota'), (500, 'HTTP 500')])
async def test_sanitized_errors(tmp_path, provider_http, status, expected):
    provider_http[1][0] = status
    manager = ModelManager(tmp_path)
    p = ProviderProfile(name='x', kind='openrouter', model='bad')
    result = await manager.test_connection(p, secret=SECRET)
    assert not result.ok and expected in result.error
    assert SECRET not in result.error


@pytest.mark.asyncio
async def test_malformed_response_no_secret(tmp_path, provider_http):
    provider_http[2][0] = True
    result = await ModelManager(tmp_path).test_connection(ProviderProfile(name='x', kind='openai', model='m'), secret=SECRET)
    assert result.error == 'Provider returned malformed response'
    assert SECRET not in result.error


@pytest.mark.asyncio
@pytest.mark.parametrize('error, expected', [(httpx.ConnectError('private ' + SECRET), 'unreachable'), (httpx.ReadTimeout(SECRET), 'Timeout')])
async def test_unreachable_local_and_timeout(tmp_path, monkeypatch, error, expected):
    def handle(request):
        raise error
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: original(**kw, transport=httpx.MockTransport(handle)))
    result = await ModelManager(tmp_path).test_connection(ProviderProfile(name='x', kind='ollama', model='m'))
    assert not result.ok and expected in result.error
    assert SECRET not in result.error


@pytest.mark.asyncio
async def test_fresh_shell_actionable_and_skip(tmp_path):
    out = []
    shell = PlainShell(AdiConfig(runtime=RuntimeConfig(type='mock')), tmp_path, out.append)
    shell.prompt = prompt_answers(['8'])
    await shell._first_run_wizard()
    await shell._handle('/provider')
    await shell._handle('/new http://127.0.0.1:3000')
    await shell._handle('Inspect the application')
    await shell.controller.wait_idle()
    assert 'No AI provider configured.' in '\n'.join(out)
    assert '/provider add' in '\n'.join(out)
    assert not shell.controller.models.list_profiles()


@pytest.mark.asyncio
async def test_tui_interactive_password_flow_and_status(tmp_path, provider_http):
    app = AdiApp(AdiConfig(runtime=RuntimeConfig(type='mock')), tmp_path)
    async with app.run_test() as pilot:
        widget = app.query_one('#input')
        async def submit(value):
            widget.value = value
            await pilot.press('enter')
            await pilot.pause()
        await submit('/provider add')
        await submit('openrouter')
        await submit('router')
        assert widget.password
        await submit(SECRET)
        assert not widget.password
        await submit('2')
        await submit('y')
        assert app.shell.controller.models.active_profile().name == 'router'
        assert 'fixture-b' in str(app.query_one('#side').render())
        await submit('/model fixture-a')
        assert 'fixture-a' in str(app.query_one('#side').render())
        # No log or event receives secret entry, even while password field is active.
        assert SECRET not in str(app.query_one('#chat').lines)
        assert SECRET not in repr(app.shell.controller.events.history)
        commands = AdiCommands(app.screen)
        for title in ['Add AI Provider', 'Switch AI Provider', 'Test Active Provider', 'Choose Model', 'Provider Settings']:
            assert [h async for h in commands.search(title)]
        app.shell.controller.models.add_profile(ProviderProfile(name='local', kind='ollama', model='local-m'))
        await submit('/provider local')
        assert 'local-m' in str(app.query_one('#side').render())


def test_cli_management(tmp_path, monkeypatch, provider_http):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('TEST_PROVIDER_KEY', SECRET)
    runner = CliRunner()
    assert 'No AI provider' in runner.invoke(app, ['providers']).output
    result = runner.invoke(app, ['provider', 'add', 'router', '--kind', 'openrouter', '--model', 'fixture-a', '--key-env', 'TEST_PROVIDER_KEY'])
    assert result.exit_code == 0, result.output
    for args in [['provider', 'list'], ['provider', 'show', 'router'], ['provider', 'test', 'router'], ['models'], ['model', 'use', 'fixture-b'], ['provider', 'use', 'router']]:
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
        assert SECRET not in result.output
    assert runner.invoke(app, ['provider', 'remove', 'router']).exit_code == 0
    assert ModelManager(tmp_path).active_profile() is None
    assert credentials.get_secret('router', 'keyring') is None


@pytest.mark.asyncio
async def test_provider_reflected_key_is_redacted_before_planning(tmp_path, monkeypatch):
    def handle(request):
        return httpx.Response(200, json={'choices': [{'message': {'content': json.dumps({'reason_summary': SECRET})}}]})
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kw: original(**kw, transport=httpx.MockTransport(handle)))
    p = ProviderProfile(name='router', kind='openrouter', model='m')
    text = await build_llm_provider(p, secret=SECRET).complete([LLMMessage(role='user', content='hi')])
    assert SECRET not in text and '<redacted>' in text
