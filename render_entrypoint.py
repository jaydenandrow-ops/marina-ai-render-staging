"""Render staging entrypoint: fail closed before loading the application."""
from __future__ import annotations

import ipaddress
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


class DeploymentConfigError(RuntimeError):
    def __init__(self, check: str, config_key: str, reason: str):
        # check/config_key are fixed labels; reason is authored here and must
        # never contain a supplied value such as a URL, password, or path.
        self.check = check
        self.config_key = config_key
        self.reason = reason
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

    database_url = values.get("GENESIS_DATABASE_URL", "").strip()
    from database_backend import is_postgres_url, validate_production_postgres_url
    if not is_postgres_url(database_url):
        raise DeploymentConfigError("database_backend", "GENESIS_DATABASE_URL",
            "GENESIS_DATABASE_URL must be a PostgreSQL URL; SQLite fallback is forbidden.")
    passed("database_backend")
    try:
        validate_production_postgres_url(database_url)
    except RuntimeError:
        raise DeploymentConfigError("database_tls_mode", "GENESIS_DATABASE_URL",
            "PostgreSQL URL must use sslmode=verify-full.") from None
    passed("database_tls_mode")
    ca_value = values.get("PGSSLROOTCERT", "")
    try:
        ca_path = Path(ca_value)
        ca_exists = bool(ca_value) and ca_path.is_file()
    except (OSError, ValueError):
        ca_exists = False
    if not ca_exists:
        raise DeploymentConfigError("database_ca_file", "PGSSLROOTCERT",
            "PGSSLROOTCERT must point to the mounted Render PostgreSQL CA file.")
    passed("database_ca_file")

    for name in ("GENESIS_ALLOWED_HOSTS", "GENESIS_CANONICAL_ORIGIN", "GENESIS_CORS_ALLOWED_ORIGINS",
                 "GENESIS_TRUSTED_PROXY_CIDRS"):
        if not values.get(name, "").strip():
            raise DeploymentConfigError("required_network_configuration", name,
                f"{name} must be explicitly configured.")

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

    cidrs = [part.strip() for part in values["GENESIS_TRUSTED_PROXY_CIDRS"].split(",") if part.strip()]
    try:
        networks = [ipaddress.ip_network(value, strict=False) for value in cidrs]
    except ValueError:
        raise DeploymentConfigError("trusted_proxy_cidrs", "GENESIS_TRUSTED_PROXY_CIDRS",
            "GENESIS_TRUSTED_PROXY_CIDRS contains an invalid CIDR.") from None
    if not networks or any(network.prefixlen == 0 for network in networks):
        raise DeploymentConfigError("trusted_proxy_cidrs", "GENESIS_TRUSTED_PROXY_CIDRS",
            "Trusted proxy CIDRs must be explicit; catch-all ranges are forbidden.")
    passed("trusted_proxy_cidrs")

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


def main() -> None:
    try:
        port = validate_runtime_environment(announce=True)
    except DeploymentConfigError as exc:
        print(f"render_startup check={exc.check} status=fail config_key={exc.config_key} reason={exc.reason}",
            file=sys.stderr, flush=True)
        raise SystemExit(2) from None
    print("render_startup check=application_handoff status=starting server=uvicorn", flush=True)
    try:
        os.execv(sys.executable, [sys.executable, "-m", "uvicorn", "staging_app:app",
            "--host", "0.0.0.0", "--port", str(port), "--workers", "1"])
    except OSError as exc:
        print(f"render_startup check=application_handoff status=fail error_class={type(exc).__name__}",
            file=sys.stderr, flush=True)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
