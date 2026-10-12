"""Minimal environment helpers for the vendored cloud adapters.

Credential-shaped names resolve through ``secret_resolver`` (Infisical/Vault/env);
everything else reads ``os.environ``.  An optional ``.env`` file at the repository
root (git-ignored) is loaded by ``load_env`` without overriding the shell.
"""

import os
from pathlib import Path

# adapters/ -> cloud-api repository root
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_env():
    """Load an optional repository-root ``.env`` into os.environ (idempotent)."""
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key not in os.environ:
                os.environ[key] = value.strip()


def _looks_like_secret(key):
    """Identify credential-shaped env names without treating normal config as secrets."""
    name = key.upper()
    markers = (
        "_TOKEN", "_SECRET", "_PASSWORD", "_PASS", "_API_KEY", "_ACCESS_KEY",
        "_PRIVATE_KEY", "_WEBHOOK_URL", "_DATABASE_URL", "_CLIENT_ID", "_CHAT_ID",
    )
    return any(name.endswith(marker) for marker in markers)


def get_env(key, default=None, required=False):
    """Get config; credential-shaped names resolve through the secret provider."""
    if _looks_like_secret(key):
        return get_secret(key, default=default, required=required)
    value = os.environ.get(key, default)
    if required and not value:
        raise ValueError(f"Required env var {key} is not set. Check .env or the environment")
    return value


def get_secret(key, default=None, required=False):
    """Resolve a secret from the configured runtime provider or env fallback."""
    from secret_resolver import SecretUnavailable, get_secret as resolve_secret

    try:
        value = resolve_secret(key, default=default, required=required)
    except SecretUnavailable:
        if required:
            raise ValueError(
                f"Required env var {key} is not set. Check .env or secret provider configuration"
            ) from None
        return default
    return value
