#!/usr/bin/env python3
"""Load and validate the central read-only cloud provider registry."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = PROJECT_ROOT / "registry" / "cloud-providers.yaml"
CAPABILITIES = frozenset({"health", "inventory", "usage", "billing"})
ADAPTER_STATUSES = frozenset({"implemented", "partial", "planned", "control_only"})
PROJECT_USAGE_STATUSES = frozenset(
    {"integrated", "documented", "planned", "adapter_only", "control_only"}
)
ENV_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
PROVIDER_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class CloudProviderRegistryError(ValueError):
    """Raised when the cloud provider registry violates its contract."""


def _string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def _validate_env_names(value: Any, label: str, errors: list[str]) -> None:
    if not _string_list(value):
        errors.append(f"{label} must be a list of environment variable names")
        return
    for name in value:
        if not ENV_NAME_PATTERN.fullmatch(name):
            errors.append(f"{label} contains an invalid environment variable name")


def validate_registry(payload: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["registry root must be a mapping"]
    if payload.get("schema_version") != "solo-empire.cloud-providers.v1":
        errors.append("schema_version must be solo-empire.cloud-providers.v1")
    if payload.get("read_only_by_default") is not True:
        errors.append("read_only_by_default must be true")
    if payload.get("write_entrypoint") != "paas:action:propose":
        errors.append("write_entrypoint must be paas:action:propose")
    if payload.get("write_actions_enabled") is not False:
        errors.append("write_actions_enabled must be false")

    providers = payload.get("providers")
    if not isinstance(providers, list) or not providers:
        return errors + ["providers must be a non-empty list"]

    seen_ids: set[str] = set()
    for index, provider in enumerate(providers):
        label = f"providers[{index}]"
        if not isinstance(provider, dict):
            errors.append(f"{label} must be a mapping")
            continue

        provider_id = provider.get("id")
        if not isinstance(provider_id, str) or not PROVIDER_ID_PATTERN.fullmatch(provider_id):
            errors.append(f"{label}.id must be a lowercase kebab-case identifier")
        elif provider_id in seen_ids:
            errors.append(f"duplicate provider id: {provider_id}")
        else:
            seen_ids.add(provider_id)

        for field in ("name", "category"):
            if not isinstance(provider.get(field), str) or not provider[field].strip():
                errors.append(f"{label}.{field} must be a non-empty string")

        cli_binary = provider.get("cli_binary")
        if cli_binary is not None and (not isinstance(cli_binary, str) or not cli_binary.strip()):
            errors.append(f"{label}.cli_binary must be a non-empty string or null")
        version_command = provider.get("cli_version_command")
        version_timeout = provider.get("cli_version_timeout_seconds", 8)
        if isinstance(version_timeout, bool) or not isinstance(version_timeout, int) or not 1 <= version_timeout <= 60:
            errors.append(f"{label}.cli_version_timeout_seconds must be an integer from 1 to 60")
        if cli_binary is not None and (
            not isinstance(version_command, list)
            or len(version_command) != 2
            or version_command[0] != cli_binary
            or version_command[1] not in {"--version", "version"}
        ):
            errors.append(f"{label}.cli_version_command must be a fixed version-only command")
        cli_install = provider.get("cli_install")
        if cli_binary is not None and (
            not isinstance(cli_install, dict)
            or not isinstance(cli_install.get("url"), str)
            or not cli_install["url"].startswith("https://")
        ):
            errors.append(f"{label}.cli_install must provide an HTTPS installation guide")

        auth = provider.get("auth")
        if not isinstance(auth, dict):
            errors.append(f"{label}.auth must be a mapping")
            auth = {}
        _validate_env_names(auth.get("env"), f"{label}.auth.env", errors)

        secret_manager = auth.get("secret_manager")
        if secret_manager is not None:
            if not isinstance(secret_manager, dict):
                errors.append(f"{label}.auth.secret_manager must be a mapping or null")
            else:
                path = secret_manager.get("path")
                if not isinstance(path, str) or not path.startswith("/") or ".." in PurePosixPath(path).parts:
                    errors.append(f"{label}.auth.secret_manager.path must be an absolute secret folder path")
                _validate_env_names(
                    secret_manager.get("names"),
                    f"{label}.auth.secret_manager.names",
                    errors,
                )

        cli_session = auth.get("cli_session")
        if cli_session is not None:
            if not isinstance(cli_session, dict):
                errors.append(f"{label}.auth.cli_session must be a mapping or null")
            else:
                check_command = cli_session.get("check_command")
                if not _string_list(check_command):
                    errors.append(f"{label}.auth.cli_session.check_command must be a non-empty string list")
                elif not cli_binary or check_command[0] != cli_binary:
                    errors.append(f"{label}.auth.cli_session.check_command must start with cli_binary")
                token_command = cli_session.get("token_command")
                if token_command is not None:
                    if not _string_list(token_command):
                        errors.append(f"{label}.auth.cli_session.token_command must be a string list or null")
                    elif not cli_binary or token_command[0] != cli_binary:
                        errors.append(f"{label}.auth.cli_session.token_command must start with cli_binary")

        capabilities = provider.get("capabilities")
        if not isinstance(capabilities, dict) or set(capabilities) != CAPABILITIES:
            errors.append(f"{label}.capabilities must define health, inventory, usage, and billing")
        elif any(not isinstance(capabilities[name], bool) for name in CAPABILITIES):
            errors.append(f"{label}.capabilities values must be booleans")

        if provider.get("adapter_status") not in ADAPTER_STATUSES:
            errors.append(f"{label}.adapter_status is invalid")
        if provider.get("write_policy") != "proposal_only":
            errors.append(f"{label}.write_policy must be proposal_only")

        if not isinstance(provider.get("paas"), bool):
            errors.append(f"{label}.paas must be a boolean")
        if provider.get("paas") is True:
            if not isinstance(provider.get("health_check"), str):
                errors.append(f"{label}.health_check is required for PaaS providers")
            for field in ("read_capabilities", "write_capabilities"):
                if not _string_list(provider.get(field)):
                    errors.append(f"{label}.{field} must be a list of strings")
            if provider.get("write_capabilities") != []:
                errors.append(f"{label}.write_capabilities must be empty")

        optional_env = provider.get("optional_env", [])
        if not _string_list(optional_env):
            errors.append(f"{label}.optional_env must be a list of environment variable names")
        else:
            for name in optional_env:
                if not ENV_NAME_PATTERN.fullmatch(name):
                    errors.append(f"{label}.optional_env contains an invalid environment variable name")

        project_usage = provider.get("project_usage")
        if not isinstance(project_usage, list):
            errors.append(f"{label}.project_usage must be a list")
            continue
        for use_index, use in enumerate(project_usage):
            use_label = f"{label}.project_usage[{use_index}]"
            if not isinstance(use, dict):
                errors.append(f"{use_label} must be a mapping")
                continue
            if not isinstance(use.get("project"), str) or not use["project"].strip():
                errors.append(f"{use_label}.project must be a non-empty string")
            if not _string_list(use.get("uses")):
                errors.append(f"{use_label}.uses must be a non-empty string list")
            if use.get("status") not in PROJECT_USAGE_STATUSES:
                errors.append(f"{use_label}.status is invalid")
            evidence = use.get("evidence")
            if not _string_list(evidence):
                errors.append(f"{use_label}.evidence must be a non-empty list of repository paths")
            else:
                for path in evidence:
                    pure_path = PurePosixPath(path)
                    if pure_path.is_absolute() or ".." in pure_path.parts:
                        errors.append(f"{use_label}.evidence contains an unsafe repository path")
            note = use.get("note")
            if note is not None and not isinstance(note, str):
                errors.append(f"{use_label}.note must be a string or null")

    return errors


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CloudProviderRegistryError("registry contains invalid YAML") from exc
    except OSError as exc:
        raise CloudProviderRegistryError("registry cannot be read") from exc

    errors = validate_registry(payload)
    if errors:
        raise CloudProviderRegistryError("; ".join(errors))
    return payload


def auth_env_names(provider: dict[str, Any]) -> list[str]:
    auth = provider.get("auth")
    return list(auth.get("env", [])) if isinstance(auth, dict) else []


def get_provider(provider_id: str) -> dict[str, Any]:
    for provider in load_registry()["providers"]:
        if provider.get("id") == provider_id:
            return provider
    raise KeyError(f"Unknown cloud provider: {provider_id}")


def secret_names(provider: dict[str, Any]) -> list[str]:
    auth = provider.get("auth")
    manager = auth.get("secret_manager") if isinstance(auth, dict) else None
    return list(manager.get("names", [])) if isinstance(manager, dict) else []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the cloud provider registry")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("use --check to validate the registry")
    try:
        registry = load_registry()
    except CloudProviderRegistryError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"OK: validated {len(registry['providers'])} cloud providers; writes use paas:action:propose.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
