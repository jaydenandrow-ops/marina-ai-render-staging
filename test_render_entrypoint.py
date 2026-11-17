"""Offline regression checks for the Render startup configuration gate."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from render_entrypoint import DeploymentConfigError, validate_runtime_environment


def valid_environment(ca_file: Path) -> dict[str, str]:
    return {
        "GENESIS_ENV": "production",
        "GENESIS_BIND_HOST": "0.0.0.0",
        "PORT": "10000",
        "GENESIS_DATABASE_URL": "postgresql://synthetic:placeholder@db.example/marina?sslmode=verify-full",
        "PGSSLROOTCERT": str(ca_file),
        "GENESIS_ALLOWED_HOSTS": "staging.example.test",
        "GENESIS_CANONICAL_ORIGIN": "https://staging.example.test",
        "GENESIS_CORS_ALLOWED_ORIGINS": "https://staging.example.test",
        "GENESIS_TRUSTED_PROXY_CIDRS": "10.23.0.0/16",
        "CLOUD_ABUSE_HMAC_SECRET": "a" * 32,
        "SECURITY_EVENT_HMAC_SECRET": "b" * 32,
        "EMAIL_AUTH_THROTTLE_SECRET": "c" * 32,
        "STAGING_BASIC_AUTH_USERNAME": "synthetic-operator",
        "STAGING_BASIC_AUTH_PASSWORD": "synthetic-password-longer-than-24",
        "CLOUD_PROVIDER_ENABLED": "0",
        "IMAGE_GENERATION_ENABLED": "0",
        "IMAGE_ACCOUNT_AUTHORIZATION_ENABLED": "0",
        "GENESIS_RESEARCH_ENABLED": "0",
        "ACCOUNT_DELETION_ENABLED": "0",
        "RETENTION_CLEANUP_ENABLED": "0",
        "RETENTION_STORAGE_CLEANUP_ENABLED": "0",
    }


class RenderEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="render-entrypoint-test-")
        self.ca_file = Path(self.temp.name) / "test-ca.pem"
        self.ca_file.write_text("synthetic only", encoding="ascii")
        self.environment = valid_environment(self.ca_file)

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_explicit_staging_configuration_passes(self):
        self.assertEqual(validate_runtime_environment(self.environment), 10000)

    def test_missing_environment_values_fail_with_safe_check_and_key(self):
        missing_cases = (
            ("GENESIS_ENV", "environment_mode"),
            ("GENESIS_BIND_HOST", "bind_host"),
            ("PORT", "assigned_port"),
            ("GENESIS_DATABASE_URL", "database_backend"),
            ("PGSSLROOTCERT", "database_ca_file"),
            ("GENESIS_TRUSTED_PROXY_CIDRS", "required_network_configuration"),
            ("CLOUD_ABUSE_HMAC_SECRET", "required_secret"),
            ("STAGING_BASIC_AUTH_PASSWORD", "staging_basic_auth"),
        )
        for key, expected_check in missing_cases:
            with self.subTest(config_key=key):
                env = dict(self.environment)
                env.pop(key)
                with self.assertRaises(DeploymentConfigError) as caught:
                    validate_runtime_environment(env)
                self.assertEqual(caught.exception.config_key, key)
                self.assertEqual(caught.exception.check, expected_check)

    def test_invalid_values_fail_closed_without_echoing_values(self):
        invalid_cases = (
            ("PORT", "not-a-port", "assigned_port"),
            ("GENESIS_DATABASE_URL", "sqlite:///private-path.db", "database_backend"),
            ("GENESIS_DATABASE_URL", "postgresql://alice:password@db.invalid/app", "database_tls_mode"),
            ("GENESIS_CANONICAL_ORIGIN", "https://[malformed", "canonical_https_origin"),
            ("GENESIS_ALLOWED_HOSTS", "staging.example.test,*", "trusted_hosts"),
            ("GENESIS_CORS_ALLOWED_ORIGINS", "https://other.invalid", "same_origin_cors"),
            ("GENESIS_TRUSTED_PROXY_CIDRS", "0.0.0.0/0", "trusted_proxy_cidrs"),
            ("IMAGE_GENERATION_ENABLED", "sometimes", "disabled_feature_flag"),
            ("IMAGE_GENERATION_ENABLED", "1", "disabled_feature_flag"),
        )
        for key, value, expected_check in invalid_cases:
            with self.subTest(config_key=key, supplied_value=value):
                env = dict(self.environment)
                env[key] = value
                with self.assertRaises(DeploymentConfigError) as caught:
                    validate_runtime_environment(env)
                self.assertEqual(caught.exception.config_key, key)
                self.assertEqual(caught.exception.check, expected_check)
                self.assertNotIn(value, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
