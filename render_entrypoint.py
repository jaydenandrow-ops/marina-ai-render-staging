"""Render staging entrypoint: fail closed before loading the application."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
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
    def __init__(self, check: str, config_key: str, reason: str, error_class: str | None = None,
            *, operation_phase: str | None = None, failure_category: str | None = None,
            sqlstate: str | None = None, mismatch_fields: tuple[str, ...] = ()):
        self.check = check
        self.config_key = config_key
        self.reason = reason
        self.error_class = error_class
        self.operation_phase = operation_phase
        self.failure_category = failure_category
        self.sqlstate = sqlstate
        self.mismatch_fields = mismatch_fields
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


_SQLSTATE_RE = re.compile(r"^[0-9A-Z]{5}$")


def _safe_sqlstate(exc: BaseException) -> str | None:
    state = getattr(exc, "sqlstate", None)
    if not isinstance(state, str):
        state = getattr(getattr(exc, "diag", None), "sqlstate", None)
    return state if isinstance(state, str) and _SQLSTATE_RE.fullmatch(state) else None


def _exception_chain(exc: BaseException):
    seen = set()
    current: BaseException | None = exc
    for _ in range(6):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _safe_connection_failure_category(exc: BaseException) -> str:
    """Classify known libpq/socket errors without returning their text."""
    chain = tuple(_exception_chain(exc))
    sqlstate = _safe_sqlstate(exc)
    if sqlstate and sqlstate.startswith("28"):
        return "authentication"
    if any(isinstance(item, (TimeoutError, socket.timeout)) for item in chain):
        return "timeout"
    if any(isinstance(item, socket.gaierror) for item in chain):
        return "dns"
    if any(isinstance(item, ssl.SSLError) for item in chain):
        return "tls"
    safe_text = " ".join(str(item).lower() for item in chain)
    if any(token in safe_text for token in (
            "could not translate host name", "name or service not known", "nodename nor servname",
            "temporary failure in name resolution", "getaddrinfo failed", "no address associated with hostname")):
        return "dns"
    if any(token in safe_text for token in (
            "password authentication failed", "authentication failed", "no password supplied",
            "role does not exist", "does not exist as a role")):
        return "authentication"
    if any(token in safe_text for token in (
            "certificate verify failed", "ssl error", "ssl syscall", "tls handshake", "server does not support ssl")):
        return "tls"
    if any(token in safe_text for token in ("connection timeout", "timed out", "timeout expired")):
        return "timeout"
    if any(token in safe_text for token in (
            "connection refused", "network is unreachable", "no route to host", "connection reset",
            "host is unreachable", "could not connect to server")):
        return "tcp"
    if sqlstate:
        return "postgres_error"
    return "connection"


def _safe_error_class(exc: BaseException) -> str:
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) else "ProviderError"


def _log_database_diagnostic(*, phase: str, category: str, error_class: str | None = None,
        sqlstate: str | None = None, mismatch_fields: tuple[str, ...] = ()) -> None:
    fields = "".join(f" field_{index}={name}" for index, name in enumerate(mismatch_fields, 1))
    cls = f" error_class={error_class}" if error_class else ""
    state = f" sqlstate={sqlstate}" if sqlstate else ""
    print(f"render_startup diagnostic=database phase={phase} category={category}{cls}{state}{fields}",
        file=sys.stderr, flush=True)


def verify_render_database_identity(values: dict[str, str] | None = None) -> None:
    """Authenticate and verify the exact private Render staging PostgreSQL target."""
    env = os.environ if values is None else values
    dsn = env.get("GENESIS_DATABASE_URL", "").strip()
    expected_host = env.get("GENESIS_RENDER_DATABASE_HOST", "").strip()
    expected_database = env.get("GENESIS_RENDER_DATABASE_NAME", "").strip()
    expected_user = env.get("GENESIS_RENDER_DATABASE_USER", "").strip()
    phase = "url_validation"
    try:
        db_backend.validate_render_internal_staging_postgres_url(dsn, staging_enabled=env.get("GENESIS_RENDER_STAGING") == "1",
            expected_host=expected_host, expected_database=expected_database, expected_user=expected_user)
        phase = "driver_import"
        import psycopg
        phase = "connection"
        with psycopg.connect(db_backend.postgres_connect_info(dsn), connect_timeout=8, autocommit=True) as conn:
            # ConnectionInfo is backed by libpq's PGconn and must be snapshotted
            # before this context exits and closes the underlying connection.
            phase = "client_metadata"
            client_host = conn.info.host
            client_hostaddr = conn.info.hostaddr
            client_port = conn.info.port
            client_database = conn.info.dbname
            client_user = conn.info.user
            phase = "identity_query"
            with conn.cursor() as cursor:
                cursor.execute("""SELECT current_database(), current_user, inet_server_addr()::text,
                    inet_server_port(), current_setting('server_version_num'), current_setting('server_encoding'),
                    (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())""")
                row = cursor.fetchone()
        phase = "identity_comparison"
        client_address = str(client_hostaddr or "").split("/", 1)[0]
        server_address = str(row[2] or "").split("/", 1)[0]
        version_num = int(row[4])
        checks = (
            ("client_host", str(client_host or "").lower() == expected_host.lower()),
            ("client_port", str(client_port or "") == "5432"),
            ("client_database", str(client_database or "") == expected_database),
            ("client_user", str(client_user or "") == expected_user),
            ("server_database", str(row[0]) == expected_database),
            ("server_user", str(row[1]) == expected_user),
            ("server_port", str(row[3]) == "5432"),
            ("server_version", version_num // 10_000 == 18),
            ("server_encoding", str(row[5]).upper() == "UTF8"),
            ("tls_active", row[6] is True),
            ("client_address_private", _is_private_render_address(client_address)),
            ("server_address_private", _is_private_render_address(server_address)),
        )
        mismatches = tuple(name for name, valid in checks if not valid)
        if mismatches:
            _log_database_diagnostic(phase=phase, category="identity_mismatch", mismatch_fields=mismatches)
            raise StagingInitializationError("database_identity", "GENESIS_DATABASE_URL",
                "Connected PostgreSQL identity, TLS state, or server properties do not match the approved Render staging target.",
                operation_phase=phase, failure_category="identity_mismatch", mismatch_fields=mismatches)
    except StagingInitializationError:
        raise
    except Exception as exc:
        category = _safe_connection_failure_category(exc) if phase in {
            "connection", "client_metadata", "identity_query"} else (
            "driver_unavailable" if phase == "driver_import" else "configuration")
        error_class = _safe_error_class(exc)
        sqlstate = _safe_sqlstate(exc)
        _log_database_diagnostic(phase=phase, category=category, error_class=error_class, sqlstate=sqlstate)
        raise StagingInitializationError("database_identity", "GENESIS_DATABASE_URL",
            "Could not verify the authorized Render staging PostgreSQL identity.", error_class,
            operation_phase=phase, failure_category=category, sqlstate=sqlstate) from None


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
