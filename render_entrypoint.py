"""Render staging entrypoint: fail closed before loading the application."""
from __future__ import annotations

import ipaddress
import os
import re
import sys
from urllib.parse import urlsplit

import database_backend as db_backend

STAGING_INITIALIZATION_CONFIRMATION = "INITIALIZE_EMPTY_MARINA_STAGING_DB"


class DeploymentConfigError(RuntimeError):
    def __init__(self, check: str, config_key: str, reason: str):
        # check/config_key are fixed labels; reason is authored here and must
        # never contain a supplied value such as a URL, password, or path.
        self.check = check
        self.config_key = config_key
        self.reason = reason
        super().__init__(reason)


class StagingInitializationError(RuntimeError):
    def __init__(self, check: str, config_key: str, reason: str, error_class: str | None = None):
        self.check = check
        self.config_key = config_key
        self.reason = reason
        self.error_class = error_class
        super().__init__(reason)


def validate_runtime_environment(env: dict[str, str] | None = None, *, announce: bool = False) -> int:
    values = os.environ if env is None else env
    if announce:
        print("render_startup phase=config_validation status=starting", flush=True)

    def passed(check: str) -> None:
        if announce:
            print(f"render_startup check={check} status=pass", flush=True)

    if values.get("GENESIS_ENV") != "production":
        raise DeploymentConfigError("environment_mode", "GENESIS_ENV",
            "GENESIS_ENV must explicitly be production for Render staging.")
    passed("environment_mode")
    if values.get("GENESIS_BIND_HOST") != "0.0.0.0":
        raise DeploymentConfigError("bind_host", "GENESIS_BIND_HOST",
            "GENESIS_BIND_HOST must be 0.0.0.0 on Render.")
    passed("bind_host")
    port_raw = values.get("PORT", "")
    if not re.fullmatch(r"[0-9]{1,5}", port_raw):
        raise DeploymentConfigError("assigned_port", "PORT", "Render PORT is required and must be numeric.")
    port = int(port_raw)
    if not 1 <= port <= 65535 or port in {18012, 18013, 19099}:
        raise DeploymentConfigError("assigned_port", "PORT", "Render PORT is outside the supported range.")
    passed("assigned_port")

    if values.get("GENESIS_RENDER_STAGING") != "1":
        raise DeploymentConfigError("render_staging_scope", "GENESIS_RENDER_STAGING",
            "GENESIS_RENDER_STAGING must explicitly be 1 for this deployment bundle.")
    passed("render_staging_scope")

    expected_host = values.get("GENESIS_RENDER_DATABASE_HOST", "").strip()
    expected_database = values.get("GENESIS_RENDER_DATABASE_NAME", "").strip()
    expected_user = values.get("GENESIS_RENDER_DATABASE_USER", "").strip()
    host_labels = expected_host.lower().split(".")
    valid_host = (len(expected_host) <= 253 and bool(expected_host)
        and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host_labels))
    try:
        ipaddress.ip_address(expected_host)
        valid_host = False
    except ValueError:
        pass
    if not valid_host:
        raise DeploymentConfigError("database_target", "GENESIS_RENDER_DATABASE_HOST",
            "Expected Render internal database hostname must be explicitly configured.")
    if expected_database != "marina_staging":
        raise DeploymentConfigError("database_target", "GENESIS_RENDER_DATABASE_NAME",
            "Render staging database name must match the approved synthetic database.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", expected_user):
        raise DeploymentConfigError("database_target", "GENESIS_RENDER_DATABASE_USER",
            "Render staging database user must be explicitly configured from the approved database identity.")
    passed("database_target")

    database_url = values.get("GENESIS_DATABASE_URL", "").strip()
    if not db_backend.is_postgres_url(database_url):
        raise DeploymentConfigError("database_backend", "GENESIS_DATABASE_URL",
            "GENESIS_DATABASE_URL must be a PostgreSQL URL; SQLite fallback is forbidden.")
    passed("database_backend")
    try:
        db_backend.validate_render_internal_staging_postgres_url(database_url, staging_enabled=True,
            expected_host=expected_host, expected_database=expected_database, expected_user=expected_user)
    except RuntimeError as exc:
        target_key = str(exc)
        if target_key not in {"GENESIS_RENDER_DATABASE_HOST", "GENESIS_RENDER_DATABASE_NAME",
                "GENESIS_RENDER_DATABASE_USER", "GENESIS_DATABASE_URL"}:
            target_key = "GENESIS_DATABASE_URL"
        check = "database_tls_mode" if target_key == "GENESIS_DATABASE_URL" else "database_target"
        raise DeploymentConfigError(check, target_key,
            "Render internal PostgreSQL URL must match the configured staging identity and TLS policy.") from None
    try:
        db_backend.validate_render_staging_libpq_environment(values)
    except RuntimeError as exc:
        name = str(exc)
        config_key = name if name in db_backend.RENDER_STAGING_FORBIDDEN_LIBPQ_ENV else "GENESIS_DATABASE_URL"
        raise DeploymentConfigError("database_libpq_overrides", config_key,
            f"{config_key} must be unset for the explicit Render staging connection.") from None
    passed("database_tls_mode")

    init_flag = values.get("MARINA_STAGING_INITIALIZE_ON_START", "0").strip()
    init_confirmation = values.get("MARINA_STAGING_INITIALIZATION_CONFIRMATION", "")
    if init_flag not in {"0", "1"}:
        raise DeploymentConfigError("staging_initialization_flag", "MARINA_STAGING_INITIALIZE_ON_START",
            "MARINA_STAGING_INITIALIZE_ON_START must be 0 or 1.")
    if init_flag == "1" and init_confirmation != STAGING_INITIALIZATION_CONFIRMATION:
        raise DeploymentConfigError("staging_initialization_authorization", "MARINA_STAGING_INITIALIZATION_CONFIRMATION",
            "Explicit staging initialization confirmation is required.")
    if init_flag == "0" and init_confirmation:
        raise DeploymentConfigError("staging_initialization_authorization", "MARINA_STAGING_INITIALIZATION_CONFIRMATION",
            "Remove the initialization confirmation when staging initialization is disabled.")
    passed("staging_initialization_authorization")

    for name in ("GENESIS_ALLOWED_HOSTS", "GENESIS_CANONICAL_ORIGIN", "GENESIS_CORS_ALLOWED_ORIGINS"):
        if not values.get(name, "").strip():
            raise DeploymentConfigError("required_network_configuration", name,
                f"{name} must be explicitly configured.")

    if values.get("GENESIS_RENDER_IGNORE_FORWARDED_HEADERS") != "1":
        raise DeploymentConfigError("render_proxy_policy", "GENESIS_RENDER_IGNORE_FORWARDED_HEADERS",
            "Render staging must explicitly ignore all forwarded headers.")
    if values.get("GENESIS_TRUSTED_PROXY_CIDRS", "").strip():
        raise DeploymentConfigError("render_proxy_policy", "GENESIS_TRUSTED_PROXY_CIDRS",
            "Render staging must not configure unverified trusted proxy networks.")

    allowed_hosts = tuple(part.strip().lower() for part in values["GENESIS_ALLOWED_HOSTS"].split(",") if part.strip())
    if not allowed_hosts or any("*" in host for host in allowed_hosts):
        raise DeploymentConfigError("trusted_hosts", "GENESIS_ALLOWED_HOSTS",
            "GENESIS_ALLOWED_HOSTS must contain explicit hosts; wildcard entries are forbidden.")

    canonical_origin = values["GENESIS_CANONICAL_ORIGIN"].strip().rstrip("/")
    try:
        parsed_origin = urlsplit(canonical_origin)
        origin_port = parsed_origin.port
    except ValueError:
        parsed_origin = None
        origin_port = None
    if (parsed_origin is None or parsed_origin.scheme != "https" or not parsed_origin.hostname
            or origin_port not in {None, 443} or parsed_origin.path not in {"", "/"}
            or parsed_origin.query or parsed_origin.fragment or parsed_origin.username or parsed_origin.password):
        raise DeploymentConfigError("canonical_https_origin", "GENESIS_CANONICAL_ORIGIN",
            "GENESIS_CANONICAL_ORIGIN must be an HTTPS origin without credentials or a path.")
    if parsed_origin.hostname.lower() not in allowed_hosts:
        raise DeploymentConfigError("canonical_host_allowlist", "GENESIS_ALLOWED_HOSTS",
            "GENESIS_ALLOWED_HOSTS must include the canonical origin hostname.")

    cors_origins = tuple(part.strip().rstrip("/") for part in values["GENESIS_CORS_ALLOWED_ORIGINS"].split(",") if part.strip())
    if not cors_origins or any(origin != canonical_origin for origin in cors_origins):
        raise DeploymentConfigError("same_origin_cors", "GENESIS_CORS_ALLOWED_ORIGINS",
            "GENESIS_CORS_ALLOWED_ORIGINS must match GENESIS_CANONICAL_ORIGIN exactly.")
    passed("network_origin_and_host_policy")

    passed("render_proxy_policy")

    for name in ("CLOUD_ABUSE_HMAC_SECRET", "SECURITY_EVENT_HMAC_SECRET", "EMAIL_AUTH_THROTTLE_SECRET"):
        if len(values.get(name, "").encode("utf-8")) < 32:
            raise DeploymentConfigError("required_secret", name, f"{name} must be configured with at least 32 bytes.")
    passed("required_secrets")
    if not values.get("STAGING_BASIC_AUTH_USERNAME", ""):
        raise DeploymentConfigError("staging_basic_auth", "STAGING_BASIC_AUTH_USERNAME",
            "Staging Basic Auth username is required.")
    if len(values.get("STAGING_BASIC_AUTH_PASSWORD", "")) < 24:
        raise DeploymentConfigError("staging_basic_auth", "STAGING_BASIC_AUTH_PASSWORD",
            "Staging Basic Auth password must be at least 24 characters.")
    passed("staging_basic_auth")

    disabled_flags = ("CLOUD_PROVIDER_ENABLED", "IMAGE_GENERATION_ENABLED",
        "IMAGE_ACCOUNT_AUTHORIZATION_ENABLED", "GENESIS_RESEARCH_ENABLED", "ACCOUNT_DELETION_ENABLED",
        "RETENTION_CLEANUP_ENABLED", "RETENTION_STORAGE_CLEANUP_ENABLED")
    false_values = {"0", "false", "no", "off"}
    true_values = {"1", "true", "yes", "on"}
    for name in disabled_flags:
        configured = values.get(name, "0").strip().lower()
        if configured not in false_values | true_values:
            raise DeploymentConfigError("disabled_feature_flag", name, f"{name} must be a valid boolean value.")
        if configured in true_values:
            raise DeploymentConfigError("disabled_feature_flag", name, f"{name} must remain disabled in synthetic staging.")
    passed("disabled_feature_flags")
    return port


def _is_private_render_address(value: object) -> bool:
    try:
        address = ipaddress.ip_address(str(value).split("/", 1)[0])
    except ValueError:
        return False
    return (address.is_private and not address.is_loopback and not address.is_link_local
        and not address.is_multicast and not address.is_unspecified and not address.is_reserved)


def verify_render_database_identity(values: dict[str, str] | None = None) -> None:
    """Authenticate and verify the exact private Render staging PostgreSQL target."""
    env = os.environ if values is None else values
    dsn = env.get("GENESIS_DATABASE_URL", "").strip()
    expected_host = env.get("GENESIS_RENDER_DATABASE_HOST", "").strip()
    expected_database = env.get("GENESIS_RENDER_DATABASE_NAME", "").strip()
    expected_user = env.get("GENESIS_RENDER_DATABASE_USER", "").strip()
    try:
        db_backend.validate_render_internal_staging_postgres_url(dsn, staging_enabled=env.get("GENESIS_RENDER_STAGING") == "1",
            expected_host=expected_host, expected_database=expected_database, expected_user=expected_user)
        import psycopg
        with psycopg.connect(db_backend.postgres_connect_info(dsn), connect_timeout=8, autocommit=True) as conn:
            client = conn.info
            with conn.cursor() as cursor:
                cursor.execute("""SELECT current_database(), current_user, inet_server_addr()::text,
                    inet_server_port(), current_setting('server_version_num'), current_setting('server_encoding'),
                    (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())""")
                row = cursor.fetchone()
        client_address = str(client.hostaddr or "").split("/", 1)[0]
        server_address = str(row[2] or "").split("/", 1)[0]
        version_num = int(row[4])
        valid = (
            str(client.host or "").lower() == expected_host.lower()
            and str(client.port or "") == "5432"
            and str(client.dbname or "") == expected_database
            and str(client.user or "") == expected_user
            and str(row[0]) == expected_database
            and str(row[1]) == expected_user
            and str(row[3]) == "5432"
            and version_num // 10_000 == 18
            and str(row[5]).upper() == "UTF8"
            and row[6] is True
            and _is_private_render_address(client_address)
            and _is_private_render_address(server_address)
        )
        if not valid:
            raise StagingInitializationError("database_identity", "GENESIS_DATABASE_URL",
                "Connected PostgreSQL identity, TLS state, or server properties do not match the approved Render staging target.")
    except StagingInitializationError:
        raise
    except Exception as exc:
        raise StagingInitializationError("database_identity", "GENESIS_DATABASE_URL",
            "Could not verify the authorized Render staging PostgreSQL identity.", type(exc).__name__) from None


def initialize_staging_database(values: dict[str, str] | None = None, *, identity_check=None,
        inspect_state=None, migrate=None, verify_ready=None, announce: bool = False) -> str:
    """Explicitly initialize only an empty Render staging schema, never import/reset data."""
    env = os.environ if values is None else values
    if env.get("MARINA_STAGING_INITIALIZE_ON_START", "0").strip() != "1":
        return "disabled"
    if env.get("GENESIS_RENDER_STAGING") != "1" or env.get("GENESIS_ENV") != "production":
        raise StagingInitializationError("staging_initialization_scope", "GENESIS_RENDER_STAGING",
            "Fresh schema initialization is limited to explicitly enabled Render staging.")
    if env.get("MARINA_STAGING_INITIALIZATION_CONFIRMATION") != STAGING_INITIALIZATION_CONFIRMATION:
        raise StagingInitializationError("staging_initialization_authorization",
            "MARINA_STAGING_INITIALIZATION_CONFIRMATION", "Explicit staging initialization confirmation is required.")
    if identity_check is None:
        identity_check = verify_render_database_identity
    if inspect_state is None:
        from migrations.postgres import inspect_migration_state
        inspect_state = inspect_migration_state
    if migrate is None:
        from migrations.postgres import migrate_fresh
        migrate = migrate_fresh
    if verify_ready is None:
        from migrations.postgres import verify_ready as verify_postgres_ready
        verify_ready = verify_postgres_ready

    try:
        identity_check(env)
        if announce:
            print("render_startup check=database_identity status=pass target=verified", flush=True)
        state = inspect_state()
        schema_state = state.get("schema_state")
        if schema_state == "empty_fresh":
            if announce:
                print("render_startup check=fresh_schema status=starting", flush=True)
            migrate()
            verify_ready()
            if announce:
                print("render_startup check=fresh_schema status=pass result=initialized", flush=True)
            return "initialized"
        if schema_state == "verified_current":
            verify_ready()
            if announce:
                print("render_startup check=fresh_schema status=pass result=already_current", flush=True)
            return "already_current"
        raise StagingInitializationError("fresh_schema", "MARINA_STAGING_INITIALIZE_ON_START",
            "Database is not empty and current; initialization refused without changing it.")
    except StagingInitializationError:
        raise
    except Exception as exc:
        raise StagingInitializationError("database_migration", "MARINA_STAGING_INITIALIZE_ON_START",
            "Staging schema initialization or readiness verification failed; application startup stopped.",
            type(exc).__name__) from None


def main() -> None:
    try:
        port = validate_runtime_environment(announce=True)
    except DeploymentConfigError as exc:
        print(f"render_startup check={exc.check} status=fail config_key={exc.config_key} reason={exc.reason}",
            file=sys.stderr, flush=True)
        raise SystemExit(2) from None
    try:
        init_result = initialize_staging_database(announce=True)
        if init_result == "disabled":
            try:
                verify_render_database_identity()
                print("render_startup check=database_identity status=pass target=verified", flush=True)
            except StagingInitializationError as exc:
                suffix = f" error_class={exc.error_class}" if exc.error_class else ""
                print(f"render_startup check={exc.check} status=fail config_key={exc.config_key} reason={exc.reason}{suffix}",
                    file=sys.stderr, flush=True)
                raise SystemExit(3) from None
            print("render_startup check=fresh_schema status=skipped authorization=disabled", flush=True)
    except StagingInitializationError as exc:
        suffix = f" error_class={exc.error_class}" if exc.error_class else ""
        print(f"render_startup check={exc.check} status=fail config_key={exc.config_key} reason={exc.reason}{suffix}",
            file=sys.stderr, flush=True)
        raise SystemExit(3) from None
    print("render_startup check=application_handoff status=starting server=uvicorn", flush=True)
    try:
        os.execv(sys.executable, [sys.executable, "-m", "uvicorn", "staging_app:app",
            "--host", "0.0.0.0", "--port", str(port), "--workers", "1", "--no-proxy-headers"])
    except OSError as exc:
        print(f"render_startup check=application_handoff status=fail error_class={type(exc).__name__}",
            file=sys.stderr, flush=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
