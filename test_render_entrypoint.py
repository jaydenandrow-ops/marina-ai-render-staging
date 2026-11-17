"""Offline regression checks for the Render startup configuration gate."""
from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import render_entrypoint as entrypoint_module
from database_backend import validate_production_postgres_url, validate_render_internal_staging_postgres_url
from render_entrypoint import (DeploymentConfigError, StagingInitializationError,
    initialize_staging_database, validate_runtime_environment, verify_render_database_identity)


def valid_environment(ca_file: Path) -> dict[str, str]:
    return {
        "GENESIS_ENV": "production",
        "GENESIS_BIND_HOST": "0.0.0.0",
        "PORT": "10000",
        "GENESIS_RENDER_STAGING": "1",
        "GENESIS_DATABASE_URL": "postgresql://marina_staging:placeholder@db.internal/marina_staging?sslmode=require",
        "GENESIS_RENDER_DATABASE_HOST": "db.internal",
        "GENESIS_RENDER_DATABASE_NAME": "marina_staging",
        "GENESIS_RENDER_DATABASE_USER": "marina_staging",
        "MARINA_STAGING_INITIALIZE_ON_START": "0",
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
            ("GENESIS_RENDER_STAGING", "render_staging_scope"),
            ("GENESIS_DATABASE_URL", "database_backend"),
                ("GENESIS_RENDER_DATABASE_HOST", "database_target"),
            ("GENESIS_RENDER_DATABASE_USER", "database_target"),
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
            ("GENESIS_DATABASE_URL", "postgresql://alice:password@db.invalid/app", "database_target", "GENESIS_RENDER_DATABASE_HOST"),
            ("GENESIS_DATABASE_URL", "postgresql://alice:password@other.internal/marina_staging?sslmode=require", "database_target", "GENESIS_RENDER_DATABASE_HOST"),
            ("GENESIS_DATABASE_URL", "postgresql://marina_staging:password@db.internal/marina_staging?sslmode=prefer", "database_tls_mode", "GENESIS_DATABASE_URL"),
            ("GENESIS_DATABASE_URL", "postgresql://someone:password@db.internal/marina_staging?sslmode=require", "database_target", "GENESIS_RENDER_DATABASE_USER"),
            ("GENESIS_DATABASE_URL", "postgresql://marina_staging:password@db.internal/other_db?sslmode=require", "database_target", "GENESIS_RENDER_DATABASE_NAME"),
            ("GENESIS_DATABASE_URL", "postgresql://marina_staging:password@db.internal:55432/marina_staging?sslmode=require", "database_tls_mode", "GENESIS_DATABASE_URL"),
            ("GENESIS_DATABASE_URL", "postgresql://marina_staging:password@db.internal/marina_staging?sslmode=require&sslrootcert=%2Ftmp%2Fca.pem", "database_tls_mode", "GENESIS_DATABASE_URL"),
            ("GENESIS_RENDER_DATABASE_NAME", "other_db", "database_target"),
            ("GENESIS_RENDER_DATABASE_USER", "other_user", "database_target"),
            ("PGSSLROOTCERT", "/old/private-ca.pem", "database_libpq_overrides"),
            ("PGHOSTADDR", "10.0.0.4", "database_libpq_overrides"),
            ("GENESIS_CANONICAL_ORIGIN", "https://[malformed", "canonical_https_origin"),
            ("GENESIS_ALLOWED_HOSTS", "staging.example.test,*", "trusted_hosts"),
            ("GENESIS_CORS_ALLOWED_ORIGINS", "https://other.invalid", "same_origin_cors"),
            ("GENESIS_TRUSTED_PROXY_CIDRS", "0.0.0.0/0", "trusted_proxy_cidrs"),
            ("IMAGE_GENERATION_ENABLED", "sometimes", "disabled_feature_flag"),
            ("IMAGE_GENERATION_ENABLED", "1", "disabled_feature_flag"),
        )
        for key, value, expected_check, *expected_config_keys in invalid_cases:
            with self.subTest(config_key=key, supplied_value=value):
                env = dict(self.environment)
                env[key] = value
                with self.assertRaises(DeploymentConfigError) as caught:
                    validate_runtime_environment(env)
                self.assertEqual(caught.exception.config_key, expected_config_keys[0] if expected_config_keys else key)
                self.assertEqual(caught.exception.check, expected_check)
                self.assertNotIn(value, str(caught.exception))

    def test_render_tls_rejects_pgsslrootcert_environment_override(self):
        env = dict(self.environment)
        env["PGSSLROOTCERT"] = "/mounted/old-ca.pem"
        with self.assertRaises(DeploymentConfigError) as caught:
            validate_runtime_environment(env)
        self.assertEqual(caught.exception.config_key, "PGSSLROOTCERT")
        self.assertNotIn("/mounted/old-ca.pem", str(caught.exception))

    def test_render_tls_exception_is_scoped_and_requires_exact_require_mode(self):
        dsn = self.environment["GENESIS_DATABASE_URL"]
        expected = {"expected_host":"db.internal", "expected_database":"marina_staging", "expected_user":"marina_staging"}
        validate_render_internal_staging_postgres_url(dsn, staging_enabled=True, **expected)
        with self.assertRaisesRegex(RuntimeError, "staging-only"):
            validate_render_internal_staging_postgres_url(dsn, staging_enabled=False, **expected)
        for mode in ("disable", "allow", "prefer", "verify-full", "verify-ca"):
            with self.subTest(sslmode=mode):
                with self.assertRaises(RuntimeError):
                    validate_render_internal_staging_postgres_url(
                        dsn.replace("sslmode=require", f"sslmode={mode}"), staging_enabled=True, **expected)
        with self.assertRaisesRegex(RuntimeError, "verify-full"):
            validate_production_postgres_url(dsn)
        validate_production_postgres_url(dsn.replace("sslmode=require", "sslmode=verify-full"))

    def test_database_identity_requires_exact_private_render_postgres18_tls_target(self):
        env = dict(self.environment)
        info = SimpleNamespace(host="db.internal", port="5432", dbname="marina_staging",
            user="marina_staging", hostaddr="10.20.1.8")
        result = ["marina_staging", "marina_staging", "10.20.1.9", 5432, "180006", "UTF8", True]

        class FakeCursor:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def execute(self, _query): return None
            def fetchone(self): return tuple(result)

        class FakeConnection:
            def __init__(self): self.info = info
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def cursor(self): return FakeCursor()

        fake_driver = SimpleNamespace(connect=lambda *_args, **_kwargs: FakeConnection())
        with patch.dict(sys.modules, {"psycopg": fake_driver}):
            verify_render_database_identity(env)
            for index, bad_value in ((0,"other_db"),(1,"other_user"),(2,"8.8.8.8"),
                    (3,5433),(4,"170006"),(5,"LATIN1"),(6,False)):
                with self.subTest(identity_field=index):
                    prior = result[index]
                    result[index] = bad_value
                    with self.assertRaises(StagingInitializationError):
                        verify_render_database_identity(env)
                    result[index] = prior
            for field, bad_value in (("host", "other.internal"), ("port", "55432"),
                    ("dbname", "other_db"), ("user", "other_user")):
                with self.subTest(client_metadata=field):
                    prior = getattr(info, field)
                    setattr(info, field, bad_value)
                    with self.assertRaises(StagingInitializationError):
                        verify_render_database_identity(env)
                    setattr(info, field, prior)
            prior_hostaddr = info.hostaddr
            info.hostaddr = "8.8.8.8"
            with self.assertRaises(StagingInitializationError):
                verify_render_database_identity(env)
            info.hostaddr = prior_hostaddr

    def test_fresh_database_initialization_is_explicit_scoped_and_idempotent(self):
        env = dict(self.environment)
        env["MARINA_STAGING_INITIALIZE_ON_START"] = "1"
        env["MARINA_STAGING_INITIALIZATION_CONFIRMATION"] = "INITIALIZE_EMPTY_MARINA_STAGING_DB"
        state = {"schema_state":"empty_fresh"}
        calls = {"identity":0,"migrate":0,"ready":0}
        def identity(_env): calls["identity"] += 1
        def inspect(): return dict(state)
        def migrate(): calls["migrate"] += 1; state["schema_state"] = "verified_current"
        def ready(): calls["ready"] += 1
        dependencies = {"identity_check":identity,"inspect_state":inspect,"migrate":migrate,"verify_ready":ready}
        self.assertEqual(initialize_staging_database(env, **dependencies), "initialized")
        self.assertEqual(initialize_staging_database(env, **dependencies), "already_current")
        self.assertEqual(calls, {"identity":2,"migrate":1,"ready":2})

    def test_initialization_refuses_nonempty_unknown_or_failed_schema(self):
        env = dict(self.environment)
        env["MARINA_STAGING_INITIALIZE_ON_START"] = "1"
        env["MARINA_STAGING_INITIALIZATION_CONFIRMATION"] = "INITIALIZE_EMPTY_MARINA_STAGING_DB"
        calls = []
        for schema_state in ("verified_upgradeable", "unexpected"):
            with self.subTest(schema_state=schema_state):
                with self.assertRaises(StagingInitializationError):
                    initialize_staging_database(env, identity_check=lambda _env: None,
                        inspect_state=lambda: {"schema_state":schema_state}, migrate=lambda: calls.append("migrate"),
                        verify_ready=lambda: calls.append("ready"))
        self.assertEqual(calls, [])
        with self.assertRaises(StagingInitializationError) as caught:
            initialize_staging_database(env, identity_check=lambda _env: None,
                inspect_state=lambda: {"schema_state":"empty_fresh"},
                migrate=lambda: (_ for _ in ()).throw(RuntimeError("private db detail")), verify_ready=lambda: None)
        self.assertNotIn("private db detail", str(caught.exception))
        self.assertEqual(caught.exception.error_class, "RuntimeError")

    def test_initialization_never_runs_without_staging_confirmation(self):
        env = dict(self.environment)
        env["MARINA_STAGING_INITIALIZE_ON_START"] = "1"
        calls = []
        with self.assertRaises(StagingInitializationError):
            initialize_staging_database(env, identity_check=lambda _env: calls.append("identity"),
                inspect_state=lambda: calls.append("inspect"), migrate=lambda: calls.append("migrate"),
                verify_ready=lambda: calls.append("ready"))
        self.assertEqual(calls, [])

    def test_normal_startup_verifies_live_database_identity_before_server_handoff(self):
        class HandoffReached(Exception):
            pass

        with patch.object(entrypoint_module, "validate_runtime_environment", return_value=10000), \
                patch.object(entrypoint_module, "initialize_staging_database", return_value="disabled"), \
                patch.object(entrypoint_module, "verify_render_database_identity") as identity_check, \
                patch.object(entrypoint_module.os, "execv", side_effect=HandoffReached):
            with self.assertRaises(HandoffReached):
                entrypoint_module.main()
        identity_check.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
