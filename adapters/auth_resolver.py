#!/usr/bin/env python3
"""Resolve provider credentials without exposing values or bypassing policy."""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal


SCRIPT_DIR = Path(__file__).resolve().parent
UTILS_DIR = SCRIPT_DIR
for directory in (SCRIPT_DIR, UTILS_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from cloud_providers import auth_env_names  # noqa: E402
from _env import load_env  # noqa: E402
from secret_resolver import (  # noqa: E402
    SecretResolutionError,
    SecretUnavailable,
    get_secret_with_source,
)


AuthStatus = Literal["configured", "not_configured", "error"]
SecretGetter = Callable[[str], tuple[str | None, str | None]]
ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]

CLI_TIMEOUT_SECONDS = 8
MAX_CLI_TOKEN_LENGTH = 16_384

load_env()


@dataclass(frozen=True)
class AuthResolution:
    status: AuthStatus
    credential: str | None = field(default=None, repr=False)
    auth_source: str | None = None
    error_class: str | None = None
    missing: tuple[str, ...] = ()


def _run_cli(
    command: object,
    *,
    binary: str,
    process_runner: ProcessRunner,
    which: Callable[[str], str | None],
) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    if (
        not isinstance(command, list)
        or not command
        or not all(isinstance(argument, str) and argument for argument in command)
        or command[0] != binary
    ):
        return None, "invalid_cli_auth_command"
    resolved = which(binary)
    if resolved is None:
        return None, "cli_not_installed"
    # Run the resolved path, like cloud_tools, so Windows .cmd shims (gcloud, az) launch.
    command = [resolved, *command[1:]]
    try:
        result = process_runner(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CLI_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return None, "cli_not_installed"
    except subprocess.TimeoutExpired:
        return None, "cli_session_timeout"
    except OSError:
        return None, "cli_session_unavailable"
    return result, None


def _resolve_cli_session(
    provider: dict[str, Any],
    missing: tuple[str, ...],
    *,
    process_runner: ProcessRunner,
    which: Callable[[str], str | None],
) -> AuthResolution:
    auth = provider.get("auth")
    cli_session = auth.get("cli_session") if isinstance(auth, dict) else None
    binary = provider.get("cli_binary")
    if not isinstance(cli_session, dict) or not isinstance(binary, str) or not binary:
        return AuthResolution(
            status="not_configured",
            error_class="credential_unavailable",
            missing=missing,
        )

    token_command = cli_session.get("token_command")
    if token_command is not None:
        token_result, token_error = _run_cli(
            token_command,
            binary=binary,
            process_runner=process_runner,
            which=which,
        )
        if token_error == "cli_not_installed":
            return AuthResolution(
                status="not_configured",
                error_class=token_error,
                missing=missing,
            )
        if token_error:
            return AuthResolution(
                status="error",
                error_class=token_error,
                missing=missing,
            )
        if token_result is not None and token_result.returncode == 0:
            token = (token_result.stdout or "").strip()
            if token:
                if len(token) > MAX_CLI_TOKEN_LENGTH or any(
                    char.isspace() for char in token
                ):
                    return AuthResolution(
                        status="error",
                        error_class="cli_token_invalid",
                        missing=missing,
                    )
                return AuthResolution(
                    status="configured",
                    credential=token,
                    auth_source="cli_session",
                    missing=(),
                )

    check_command = cli_session.get("check_command")
    check_result, check_error = _run_cli(
        check_command,
        binary=binary,
        process_runner=process_runner,
        which=which,
    )
    if check_error:
        status: AuthStatus = (
            "error" if check_error != "cli_not_installed" else "not_configured"
        )
        return AuthResolution(
            status=status,
            error_class=check_error,
            missing=missing,
        )
    if check_result is not None and check_result.returncode == 0:
        return AuthResolution(
            status="configured",
            auth_source="cli_session",
            missing=(),
        )
    return AuthResolution(
        status="not_configured",
        error_class="cli_session_not_authenticated",
        missing=missing,
    )


def resolve_provider_auth(
    provider: dict[str, Any],
    *,
    secret_getter: SecretGetter | None = None,
    process_runner: ProcessRunner | None = None,
    which: Callable[[str], str | None] | None = None,
) -> AuthResolution:
    """Try the configured secret policy first, then a registered CLI session."""
    getter = secret_getter or get_secret_with_source
    runner = process_runner or subprocess.run
    find_cli = which or shutil.which
    names = auth_env_names(provider)
    missing = tuple(names)

    for name in names:
        try:
            credential, source = getter(name)
        except SecretUnavailable:
            continue
        except SecretResolutionError:
            return AuthResolution(
                status="error",
                auth_source="secret_manager",
                error_class="secret_provider_unreachable",
                missing=missing,
            )
        if credential and credential.strip():
            auth_source = "env" if source == "env" else "secret_manager"
            return AuthResolution(
                status="configured",
                credential=credential.strip(),
                auth_source=auth_source,
                missing=(),
            )

    return _resolve_cli_session(
        provider,
        missing,
        process_runner=runner,
        which=find_cli,
    )
