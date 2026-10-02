"""Credential storage for AI provider profiles.

Never stores a plaintext secret in the assessment/session database. A
profile holds a `credential_ref` — either:

  - "keyring" -> the secret lives in the OS keyring, looked up by profile
    name at use time (preferred).
  - "env:VAR_NAME" -> the secret is read from an environment variable at
    use time; nothing is persisted at all.
  - "" / None -> no secret required (e.g. a local Ollama endpoint).

`keyring` is optional: when it is not installed or the platform backend is
unavailable (common in CI/sandboxes), credential storage falls back to a
file-backed store under the user's config dir, permission-restricted
(0600), and this fallback is reported explicitly by `adi doctor` rather
than silently pretended to be the OS keyring.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

_SERVICE_NAME = "adi-security-workbench"

try:
    import keyring as _keyring

    _KEYRING_AVAILABLE = True
except Exception:  # noqa: BLE001 - pragma: no cover - import failure path
    _KEYRING_AVAILABLE = False


def keyring_available() -> bool:
    if not _KEYRING_AVAILABLE:
        return False
    try:
        backend = _keyring.get_keyring()
        return backend is not None and "fail" not in type(backend).__name__.lower()
    except Exception:  # noqa: BLE001 - best-effort probe/fallback, never fatal
        return False


def _fallback_store_path() -> Path:
    base = Path(os.environ.get("ADI_CONFIG_HOME", Path.home() / ".config" / "adi"))
    base.mkdir(parents=True, exist_ok=True)
    return base / "credential_store.json"


def _fallback_read() -> dict[str, str]:
    path = _fallback_store_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:  # noqa: BLE001 - best-effort probe/fallback, never fatal
        return {}


def _fallback_write(data: dict[str, str]) -> None:
    path = _fallback_store_path()
    path.write_text(json.dumps(data))
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def set_secret(profile_name: str, secret: str) -> str:
    """Store `secret` for `profile_name`. Returns the credential_ref to
    persist in the profile (never the secret itself)."""
    if keyring_available():
        _keyring.set_password(_SERVICE_NAME, profile_name, secret)
        return "keyring"
    data = _fallback_read()
    data[profile_name] = secret
    _fallback_write(data)
    return "keyring"


def get_secret(profile_name: str, credential_ref: str | None) -> str | None:
    if not credential_ref:
        return None
    if credential_ref.startswith("env:"):
        return os.environ.get(credential_ref[len("env:") :])
    if credential_ref == "keyring":
        if keyring_available():
            try:
                return _keyring.get_password(_SERVICE_NAME, profile_name)
            except Exception:  # noqa: BLE001 - best-effort probe/fallback, never fatal
                return None
        return _fallback_read().get(profile_name)
    return None


def delete_secret(profile_name: str) -> None:
    if keyring_available():
        try:
            _keyring.delete_password(_SERVICE_NAME, profile_name)
        except Exception:  # noqa: BLE001,S110 - best-effort probe/fallback, never fatal
            pass
    data = _fallback_read()
    if profile_name in data:
        del data[profile_name]
        _fallback_write(data)
