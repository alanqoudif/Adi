"""Shared interactive onboarding. Secrets only travel to the credential gateway."""
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from adi.llm.base import LLMError
from adi.product.models import ModelManager, ProviderProfile, default_locality

CHOICES = [
    ('OpenAI', 'openai'), ('Anthropic', 'anthropic'), ('OpenRouter', 'openrouter'),
    ('Ollama', 'ollama'), ('LM Studio', 'lmstudio'), ('vLLM', 'vllm'),
    ('Custom OpenAI-compatible', 'openai-compatible'),
]
MENU = 'Connect AI:\n' + '\n'.join(
    f'  {i}. {label}' for i, (label, _) in enumerate(CHOICES, 1)
) + '\n  8. Continue without AI'
Prompt = Callable[[str, bool], Awaitable[str]]


def validate_profile(profile: ProviderProfile) -> None:
    if not profile.name.strip() or len(profile.name) > 80 or any(
        not (c.isalnum() or c in '-_.') for c in profile.name
    ):
        raise LLMError('Profile name must contain only letters, numbers, dash, dot or underscore.')
    url = urlsplit(profile.resolved_base_url() or '')
    if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise LLMError('Invalid endpoint. Use an HTTP(S) base URL without credentials or query parameters.')
    if not profile.model.strip():
        raise LLMError('Model ID is required.')


def test_message(result) -> str:
    if result.ok:
        return '✓ API reachable\n✓ Authentication accepted\n✓ Model available\n✓ Response received'
    return f'Connection test failed: {result.error}'


async def setup_provider(
    manager: ModelManager, prompt: Prompt, emit: Callable[[str], None],
    edit: str | None = None, choice: str | None = None,
) -> bool:
    old = manager.require_profile(edit) if edit else None
    if old:
        kind = old.kind
        name = old.name
    else:
        emit(MENU)
        choice = (choice or await prompt('Choose provider (1–8, /cancel): ', False)).strip().lower()
        if choice in ('8', 'skip', '/cancel', 'continue without ai'):
            emit('Continue without AI. Run /provider add whenever you are ready.')
            return False
        kind = next((k for label, k in CHOICES if choice in (k, label.lower())), None)
        if choice.isdigit() and 1 <= int(choice) <= len(CHOICES):
            kind = CHOICES[int(choice) - 1][1]
        if not kind:
            raise LLMError('Choose a provider from the menu.')
        name = (await prompt(f'Profile name [{kind}]: ', False)).strip() or kind
        if name in manager.store.profiles:
            raise LLMError('Profile already exists. Use /provider edit <name>.')
    draft = old.model_copy() if old else ProviderProfile(
        name=name, kind=kind, locality=default_locality(kind),
    )
    if kind in ('ollama', 'lmstudio', 'vllm', 'openai-compatible'):
        default = draft.resolved_base_url() or ''
        draft.base_url = (await prompt(f'Base URL [{default}]: ', False)).strip() or default
    # Validate endpoint/name before handling credentials or making network calls.
    validate_profile(draft.model_copy(update={'model': draft.model or 'pending'}))
    secret = '' if kind == 'ollama' else (await prompt(
        'API key (blank keeps existing key; optional for local/custom): ', True
    )).strip()
    if kind in ('openai', 'openrouter', 'anthropic') and not secret and not draft.credential_ref:
        raise LLMError('API key is required for this provider.')
    emit('Discovering available models…')
    models = await manager.list_models(draft, secret=secret or None)
    if models:
        for i, model in enumerate(models, 1):
            emit(f'  {i}. {model}')
    else:
        emit('Model discovery unavailable. Enter the model ID manually.')
    selected = (await prompt(f'Model number or ID [{draft.model}]: ', False)).strip()
    if selected.isdigit() and 1 <= int(selected) <= len(models):
        selected = models[int(selected) - 1]
    draft.model = selected or draft.model
    validate_profile(draft)
    answer = (await prompt('Test connection? [Y/n]: ', False)).strip().lower()
    if answer not in ('n', 'no'):
        result = await manager.test_connection(draft, secret=secret or None)
        emit(test_message(result))
        if not result.ok:
            emit('Provider was not saved. Check the endpoint, key and model, then retry.')
            return False
    else:
        emit('Connection unverified (test skipped).')
    manager.add_profile(draft, secret=secret or None)
    manager.set_active(draft.name)
    if secret:
        from adi.product.credentials import keyring_available

        emit('✓ Credentials stored securely' if keyring_available() else
             '✓ Credentials stored in permission-restricted fallback (OS keyring unavailable)')
    emit(f'✓ Provider saved\n✓ Active provider: {draft.name}\n✓ Model: {draft.model}')
    return True
