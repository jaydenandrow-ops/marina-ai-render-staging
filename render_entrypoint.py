"""Render staging entrypoint: fail closed before loading the application."""
from __future__ import annotations

import ipaddress
import os
import re
import sys
from pathlib import Path


class DeploymentConfigError(RuntimeError):
    pass


def validate_runtime_environment(env: dict[str, str] | None = None) -> int:
    values = os.environ if env is None else env
    if values.get("GENESIS_ENV") != "production":
        raise DeploymentConfigError("GENESIS_ENV must explicitly be production for Render staging.")
    if values.get("GENESIS_BIND_HOST") != "0.0.0.0":
        raise DeploymentConfigError("GENESIS_BIND_HOST must be 0.0.0.0 on Render.")
    port_raw = values.get("PORT", "")
    if not re.fullmatch(r"[0-9]{1,5}", port_raw):
        raise DeploymentConfigError("Render PORT is required and must be numeric.")
    port = int(port_raw)
    if not 1 <= port <= 65535 or port in {18012, 18013, 19099}:
        raise DeploymentConfigError("Render PORT is outside the supported range.")

    database_url = values.get("GENESIS_DATABASE_URL", "").strip()
    from database_backend import is_postgres_url, validate_production_postgres_url
    if not is_postgres_url(database_url):
        raise DeploymentConfigError("GENESIS_DATABASE_URL must be a PostgreSQL URL; SQLite fallback is forbidden.")
    try:
        validate_production_postgres_url(database_url)
    except RuntimeError:
        raise DeploymentConfigError("PostgreSQL URL must use sslmode=verify-full.") from None
    ca_path = Path(values.get("PGSSLROOTCERT", ""))
    if not values.get("PGSSLROOTCERT") or not ca_path.is_file():
        raise DeploymentConfigError("PGSSLROOTCERT must point to the mounted Render PostgreSQL CA file.")

    for name in ("GENESIS_ALLOWED_HOSTS", "GENESIS_CANONICAL_ORIGIN", "GENESIS_CORS_ALLOWED_ORIGINS",
                 "GENESIS_TRUSTED_PROXY_CIDRS"):
        if not values.get(name, "").strip():
            raise DeploymentConfigError(f"{name} must be explicitly configured.")
    cidrs = [part.strip() for part in values["GENESIS_TRUSTED_PROXY_CIDRS"].split(",") if part.strip()]
    try:
        networks = [ipaddress.ip_network(value, strict=False) for value in cidrs]
    except ValueError:
        raise DeploymentConfigError("GENESIS_TRUSTED_PROXY_CIDRS contains an invalid CIDR.") from None
    if not networks or any(network.prefixlen == 0 for network in networks):
        raise DeploymentConfigError("Trusted proxy CIDRs must be explicit; catch-all ranges are forbidden.")

    for name in ("CLOUD_ABUSE_HMAC_SECRET", "SECURITY_EVENT_HMAC_SECRET", "EMAIL_AUTH_THROTTLE_SECRET"):
        if len(values.get(name, "").encode("utf-8")) < 32:
            raise DeploymentConfigError(f"{name} must be configured with at least 32 bytes.")
    if not values.get("STAGING_BASIC_AUTH_USERNAME", "") or len(values.get("STAGING_BASIC_AUTH_PASSWORD", "")) < 24:
        raise DeploymentConfigError("Staging Basic Auth credentials are required; password must be at least 24 characters.")

    disabled_flags = ("CLOUD_PROVIDER_ENABLED", "IMAGE_GENERATION_ENABLED",
        "IMAGE_ACCOUNT_AUTHORIZATION_ENABLED", "GENESIS_RESEARCH_ENABLED", "ACCOUNT_DELETION_ENABLED",
        "RETENTION_CLEANUP_ENABLED", "RETENTION_STORAGE_CLEANUP_ENABLED")
    for name in disabled_flags:
        if values.get(name, "0").strip().lower() in {"1", "true", "yes", "on"}:
            raise DeploymentConfigError(f"{name} must remain disabled in synthetic staging.")
    return port


def main() -> None:
    try:
        port = validate_runtime_environment()
    except DeploymentConfigError as exc:
        print(f"Render staging startup refused: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    os.execv(sys.executable, [sys.executable, "-m", "uvicorn", "staging_app:app",
        "--host", "0.0.0.0", "--port", str(port), "--workers", "1"])


if __name__ == "__main__":
    main()
