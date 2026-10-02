"""Scriptable management and interactive setup using the same product gateway."""
import asyncio
import os

import typer

from adi.config.settings import load_config
from adi.llm.base import LLMError
from adi.product.models import ModelManager, ProviderProfile, default_locality
from adi.product.onboarding import setup_provider, test_message, validate_profile
from adi.product.plain_shell import PlainShell

provider_app = typer.Typer(help='Connect and manage AI provider profiles.')
model_app = typer.Typer(help='Discover and choose AI models.')


def output(text):
    typer.echo(text)


@provider_app.command('list')
def providers():
    manager = ModelManager()
    if not manager.list_profiles():
        output('No AI provider configured. Run adi provider add.')
    for p in manager.list_profiles():
        output(f'{p.name} | {p.kind} | {p.model}' + (' (active)' if manager.store.active_profile == p.name else ''))


@provider_app.command('show')
def show(name: str):
    try:
        p = ModelManager().require_profile(name)
        output(f'{p.name} | {p.kind} | {p.model} | {p.resolved_base_url()}\nCredentials: ' + ('stored reference' if p.credential_ref else 'none'))
    except LLMError as exc:
        output(str(exc))
        raise typer.Exit(1) from None


@provider_app.command('add')
def add(
    name: str | None = typer.Argument(None),
    kind: str | None = typer.Option(None, '--kind'),
    model: str = typer.Option('', '--model'),
    base_url: str | None = typer.Option(None, '--base-url'),
    key_env: str | None = typer.Option(None, '--key-env', help='Read API key from this environment variable, never from argv.'),
    test: bool = typer.Option(True, '--test/--no-test'),
):
    manager = ModelManager()
    try:
        if kind is None:
            shell = PlainShell(load_config())
            asyncio.run(setup_provider(manager, shell.prompt, output))
            return
        if not name:
            raise LLMError('Profile name is required with --kind.')
        if name in manager.store.profiles:
            raise LLMError('Profile already exists. Use adi provider edit <name>.')
        profile = ProviderProfile(name=name, kind=kind, model=model, base_url=base_url, locality=default_locality(kind))
        validate_profile(profile)
        secret = os.environ.get(key_env) if key_env else None
        if kind in ('openai', 'anthropic', 'openrouter') and not secret:
            raise LLMError('API key required. Use --key-env or interactive adi provider add.')
        if test:
            result = asyncio.run(manager.test_connection(profile, secret=secret))
            output(test_message(result))
            if not result.ok:
                raise typer.Exit(1)
        else:
            output('Connection unverified (test skipped).')
        manager.add_profile(profile, secret=secret)
        manager.set_active(name)
        output(f'Provider saved. Active provider: {name} | Model: {model}')
    except (LLMError, ValueError):
        output('Invalid provider configuration. Check name, kind, endpoint, model and API key requirements.')
        raise typer.Exit(1) from None


@provider_app.command('edit')
def edit(name: str):
    try:
        shell = PlainShell(load_config())
        asyncio.run(setup_provider(shell.controller.models, shell.prompt, output, edit=name))
    except (LLMError, ValueError) as exc:
        output(str(exc))
        raise typer.Exit(1) from None


@provider_app.command('test')
def test_provider(name: str):
    try:
        result = asyncio.run(ModelManager().test_connection(ModelManager().require_profile(name)))
        output(test_message(result))
        if not result.ok:
            raise typer.Exit(1)
    except LLMError as exc:
        output(str(exc))
        raise typer.Exit(1) from None


@provider_app.command('use')
def use(name: str):
    try:
        ModelManager().set_active(name)
        output(f'Active provider: {name}')
    except LLMError as exc:
        output(str(exc))
        raise typer.Exit(1) from None


@provider_app.command('remove')
def remove(name: str):
    try:
        ModelManager().remove_profile(name)
        output('Provider and credentials removed.')
    except LLMError as exc:
        output(str(exc))
        raise typer.Exit(1) from None


@model_app.command('list')
def models():
    manager = ModelManager()
    profile = manager.active_profile()
    if profile is None:
        output('No AI provider configured. Run adi provider add.')
        raise typer.Exit(1)
    ids = asyncio.run(manager.list_models(profile))
    output('\n'.join(ids) if ids else 'Discovery unavailable. Use adi model use <id>.')


@model_app.command('show')
def model_show():
    profile = ModelManager().active_profile()
    output(profile.model if profile else 'No AI provider configured. Run adi provider add.')


@model_app.command('use')
def model_use(model: str):
    try:
        ModelManager().set_model(model)
        output(f'Model: {model}')
    except LLMError as exc:
        output(str(exc))
        raise typer.Exit(1) from None
