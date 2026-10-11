#!/usr/bin/env python3
"""Offline tests for provider secret and CLI-session auth resolution."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
PLATFORM_SCRIPTS = ROOT / "adapters"
UTILS = ROOT / "adapters"
for directory in (PLATFORM_SCRIPTS, UTILS):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from auth_resolver import resolve_provider_auth  # noqa: E402
from cloud_providers import get_provider  # noqa: E402
from secret_resolver import SecretResolutionError  # noqa: E402


class AuthResolverTest(unittest.TestCase):
    def test_secret_manager_and_environment_sources_precede_cli(self):
        runner = Mock()
        secret_auth = resolve_provider_auth(
            get_provider("vercel"),
            secret_getter=lambda _name: ("secret-value", "infisical"),
            process_runner=runner,
            which=lambda _binary: "C:\\Tools\\vercel.exe",
        )
        env_auth = resolve_provider_auth(
            get_provider("vercel"),
            secret_getter=lambda _name: ("env-value", "env"),
            process_runner=runner,
            which=lambda _binary: "C:\\Tools\\vercel.exe",
        )

        self.assertEqual(secret_auth.auth_source, "secret_manager")
        self.assertEqual(secret_auth.credential, "secret-value")
        self.assertEqual(env_auth.auth_source, "env")
        self.assertEqual(env_auth.credential, "env-value")
        runner.assert_not_called()
        self.assertNotIn("secret-value", repr(secret_auth))

    def test_whitespace_only_credential_is_not_configured(self):
        auth = resolve_provider_auth(
            get_provider("vercel"),
            secret_getter=lambda _name: ("  \n ", "env"),
            process_runner=Mock(),
            which=lambda _binary: None,
        )

        self.assertEqual(auth.status, "not_configured")
        self.assertEqual(auth.error_class, "cli_not_installed")
        self.assertIsNone(auth.credential)

    def test_railway_whoami_confirms_a_cli_session_without_returning_identity(self):
        runner = Mock(
            return_value=subprocess.CompletedProcess(
                args=["railway", "whoami"],
                returncode=0,
                stdout="private-account-name\n",
                stderr="",
            )
        )
        auth = resolve_provider_auth(
            get_provider("railway"),
            secret_getter=lambda _name: (None, None),
            process_runner=runner,
            which=lambda _binary: "C:\\Tools\\railway.exe",
        )

        self.assertEqual(auth.status, "configured")
        self.assertIsNone(auth.credential)
        self.assertEqual(auth.auth_source, "cli_session")
        self.assertNotIn("private-account-name", repr(auth))
        self.assertEqual(runner.call_args.args[0], ["C:\\Tools\\railway.exe", "whoami"])
        self.assertIs(runner.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_vercel_whoami_confirms_a_cli_session_without_returning_identity(self):
        runner = Mock(
            return_value=subprocess.CompletedProcess(
                args=["vercel", "whoami"],
                returncode=0,
                stdout="private-vercel-account\n",
                stderr="",
            )
        )
        auth = resolve_provider_auth(
            get_provider("vercel"),
            secret_getter=lambda _name: (None, None),
            process_runner=runner,
            which=lambda _binary: "C:\\Tools\\vercel.exe",
        )

        self.assertEqual(auth.status, "configured")
        self.assertIsNone(auth.credential)
        self.assertEqual(auth.auth_source, "cli_session")
        self.assertNotIn("private-vercel-account", repr(auth))
        self.assertEqual(runner.call_args.args[0], ["C:\\Tools\\vercel.exe", "whoami"])

    def test_gh_auth_token_is_captured_for_api_use_but_never_repr_or_metadata(self):
        runner = Mock(
            return_value=subprocess.CompletedProcess(
                args=["gh", "auth", "token"],
                returncode=0,
                stdout="github-private-token\n",
                stderr="",
            )
        )
        auth = resolve_provider_auth(
            get_provider("github"),
            secret_getter=lambda _name: (None, None),
            process_runner=runner,
            which=lambda _binary: "C:\\Tools\\gh.exe",
        )

        self.assertEqual(auth.status, "configured")
        self.assertEqual(auth.credential, "github-private-token")
        self.assertEqual(auth.auth_source, "cli_session")
        self.assertNotIn("github-private-token", repr(auth))

    def test_missing_cli_and_unauthenticated_cli_are_reported_without_output(self):
        missing_cli = resolve_provider_auth(
            get_provider("vercel"),
            secret_getter=lambda _name: (None, None),
            process_runner=Mock(),
            which=lambda _binary: None,
        )
        not_logged_in = resolve_provider_auth(
            get_provider("railway"),
            secret_getter=lambda _name: (None, None),
            process_runner=Mock(
                return_value=subprocess.CompletedProcess(
                    args=["railway", "whoami"],
                    returncode=1,
                    stdout="private login detail",
                    stderr="private error detail",
                )
            ),
            which=lambda _binary: "C:\\Tools\\railway.exe",
        )

        self.assertEqual(missing_cli.status, "not_configured")
        self.assertEqual(missing_cli.error_class, "cli_not_installed")
        self.assertEqual(not_logged_in.status, "not_configured")
        self.assertEqual(not_logged_in.error_class, "cli_session_not_authenticated")
        self.assertNotIn("private", repr(not_logged_in))

    def test_secret_provider_failure_does_not_fall_through_to_cli(self):
        runner = Mock()
        auth = resolve_provider_auth(
            get_provider("github"),
            secret_getter=Mock(side_effect=SecretResolutionError("private provider detail")),
            process_runner=runner,
            which=lambda _binary: "C:\\Tools\\gh.exe",
        )

        self.assertEqual(auth.status, "error")
        self.assertEqual(auth.auth_source, "secret_manager")
        self.assertEqual(auth.error_class, "secret_provider_unreachable")
        self.assertNotIn("private provider detail", repr(auth))
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
