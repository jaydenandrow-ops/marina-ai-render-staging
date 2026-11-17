from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import sqlite3
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncIterator, Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from conversation import bound_cloud_history, build_system_prompt, detect_language, image_unavailable_message, is_image_request
from providers import AIProvider, OllamaProvider, OpenAIResponsesProvider, ProviderError
from research_adapter import ResearchAdapterError, ZeroGenesisResearchAdapter
from resources import memory_status
from image_generation import MAX_PROMPT_CHARS as IMAGE_MAX_PROMPT_CHARS, ImageGenerationError, ImageGenerationService
from migrations import MigrationError, dry_run as inspect_migration_database, migrate as migrate_database
from migrations.versions import CLOUD_BUDGET_MIGRATIONS
from database_safety import validate_test_database_configuration, validate_test_database_path
from database_backend import (checkout_postgres, close_postgres_pool, database_url, is_postgres_url,
    postgres_connection, validate_production_postgres_url, validate_test_postgres_url)

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("GENESIS_DB_PATH", str(ROOT / "genesis.db")))
_configured_cloud_budget_path = os.getenv("CLOUD_BUDGET_DB_PATH", "").strip()
CLOUD_BUDGET_DB_PATH = Path(_configured_cloud_budget_path) if _configured_cloud_budget_path else DB_PATH
_CLOUD_BUDGET_PATH_WAS_DEFAULTED = not bool(_configured_cloud_budget_path)
_CLOUD_BUDGET_IMPORT_DEFAULT = CLOUD_BUDGET_DB_PATH
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
_ollama_host = urlsplit(OLLAMA_URL).hostname
if _ollama_host not in {"127.0.0.1", "localhost", "::1"}:
    raise RuntimeError("OLLAMA_URL must point to a loopback address")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "").strip()
SUPPORTED_GENESIS_ENVS = frozenset({"development", "test", "production"})


def validate_genesis_env(value: str | None) -> str:
    normalized = value.strip().lower() if value is not None else ""
    if normalized not in SUPPORTED_GENESIS_ENVS:
        raise RuntimeError("GENESIS_ENV is required and must be development, test, or production.")
    return normalized


def validate_bind_configuration(environment: str, bind_host: str, *, explicitly_configured: bool) -> bool:
    try:
        loopback = ipaddress.ip_address(bind_host).is_loopback
    except ValueError:
        loopback = False
    if environment != "production" and not loopback:
        raise RuntimeError("Non-loopback GENESIS_BIND_HOST requires explicit GENESIS_ENV=production.")
    if environment == "production" and not explicitly_configured:
        raise RuntimeError("GENESIS_BIND_HOST must be explicitly configured in production.")
    return loopback


GENESIS_ENV = validate_genesis_env(os.getenv("GENESIS_ENV"))
GENESIS_DATABASE_URL = database_url()
DATABASE_BACKEND = "postgresql" if is_postgres_url(GENESIS_DATABASE_URL) else "sqlite"
if GENESIS_DATABASE_URL and DATABASE_BACKEND != "postgresql":
    raise RuntimeError("GENESIS_DATABASE_URL must be a supported PostgreSQL URL; SQLite continues to use GENESIS_DB_PATH.")
if GENESIS_ENV == "test" and DATABASE_BACKEND == "postgresql":
    validate_test_postgres_url(GENESIS_DATABASE_URL)
elif GENESIS_ENV == "test":
    validate_test_database_configuration(DB_PATH, CLOUD_BUDGET_DB_PATH,
        environment=GENESIS_ENV, project_root=ROOT)
if DATABASE_BACKEND == "postgresql" and (os.getenv("CLOUD_BUDGET_DB_PATH", "").strip()
        or os.getenv("CLOUD_BUDGET_DATABASE_URL", "").strip()):
    raise RuntimeError("PostgreSQL currently requires app and cloud-budget tables in the same database.")
if GENESIS_ENV == "production" and DATABASE_BACKEND == "postgresql":
    validate_production_postgres_url(GENESIS_DATABASE_URL)
GENESIS_BIND_HOST = os.getenv("GENESIS_BIND_HOST", "127.0.0.1").strip().lower()
_bind_is_loopback = validate_bind_configuration(GENESIS_ENV, GENESIS_BIND_HOST,
    explicitly_configured=bool(os.getenv("GENESIS_BIND_HOST", "").strip()))
_default_hosts = "127.0.0.1,localhost,::1,testserver"
TRUSTED_HOSTS = tuple(x.strip().lower() for x in os.getenv("GENESIS_ALLOWED_HOSTS", _default_hosts).split(",") if x.strip())
CANONICAL_ORIGIN = os.getenv("GENESIS_CANONICAL_ORIGIN", "").strip().rstrip("/")
_origin_parts = urlsplit(CANONICAL_ORIGIN) if CANONICAL_ORIGIN else None
if CANONICAL_ORIGIN and (_origin_parts.scheme not in {"http", "https"} or not _origin_parts.hostname
        or _origin_parts.path not in {"", "/"} or _origin_parts.query or _origin_parts.fragment
        or _origin_parts.username or _origin_parts.password):
    raise RuntimeError("GENESIS_CANONICAL_ORIGIN must be an absolute HTTP(S) origin without credentials or path.")
_proxy_values = [x.strip() for x in os.getenv("GENESIS_TRUSTED_PROXY_CIDRS", "").split(",") if x.strip()]
try:
    TRUSTED_PROXY_NETWORKS = tuple(ipaddress.ip_network(value, strict=False) for value in _proxy_values)
except ValueError as exc:
    raise RuntimeError("GENESIS_TRUSTED_PROXY_CIDRS contains an invalid CIDR.") from exc

def validate_cors_origins(canonical_origin: str, configured: str) -> tuple[str, ...]:
    origins = tuple(x.strip().rstrip("/") for x in configured.split(",") if x.strip())
    if any(origin != canonical_origin for origin in origins):
        raise RuntimeError("CORS is same-origin only; each allowed origin must exactly match GENESIS_CANONICAL_ORIGIN.")
    return origins


def validate_production_network_config(environment: str, *, allowed_hosts: str,
                                       canonical_origin: str,
                                       cors_origins: tuple[str, ...]) -> None:
    if environment != "production":
        return
    parsed = urlsplit(canonical_origin)
    if not allowed_hosts.strip():
        raise RuntimeError("GENESIS_ALLOWED_HOSTS is required in production.")
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("A canonical HTTPS GENESIS_CANONICAL_ORIGIN is required in production.")
    if canonical_origin not in cors_origins:
        raise RuntimeError("GENESIS_CORS_ALLOWED_ORIGINS must explicitly contain the canonical origin in production.")


CORS_ALLOWED_ORIGINS = validate_cors_origins(CANONICAL_ORIGIN,
    os.getenv("GENESIS_CORS_ALLOWED_ORIGINS", CANONICAL_ORIGIN))
validate_production_network_config(GENESIS_ENV, allowed_hosts=os.getenv("GENESIS_ALLOWED_HOSTS", ""),
    canonical_origin=CANONICAL_ORIGIN, cors_origins=CORS_ALLOWED_ORIGINS)
SECURITY_LOGGER = logging.getLogger("marina.security")


def _secret_setting(name: str, local_default: str) -> bytes:
    raw = os.getenv(name, "")
    if GENESIS_ENV == "production" and (len(raw.encode("utf-8")) < 32 or raw in {
            "local-development-abuse-key-not-for-production",
            "local-development-event-key-not-for-production"}):
        raise RuntimeError(f"{name} must contain at least 32 bytes in production.")
    return raw.encode("utf-8") if raw else local_default.encode("utf-8")


ABUSE_HMAC_SECRET = _secret_setting("CLOUD_ABUSE_HMAC_SECRET", "local-development-abuse-key-not-for-production")
SECURITY_EVENT_HMAC_SECRET = _secret_setting("SECURITY_EVENT_HMAC_SECRET", "local-development-event-key-not-for-production")
MAX_MESSAGE_CHARS = 20_000
MAX_WAITING_REQUESTS = 3
QUEUE_TIMEOUT = 120
LOW_MEMORY_BYTES = 400 * 1024 * 1024


def bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer between {minimum} and {maximum}.") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be an integer between {minimum} and {maximum}.")
    return value


MAX_API_BODY_BYTES = bounded_env_int("MAX_API_BODY_BYTES", 64 * 1024, 1024, 1024 * 1024)
MAX_CHAT_BODY_BYTES = bounded_env_int("MAX_CHAT_BODY_BYTES", 100 * 1024, 1024, 1024 * 1024)

ANON_SESSION_GLOBAL_PER_DAY = bounded_env_int("ANON_SESSION_GLOBAL_PER_DAY", 10000, 1, 1000000)
ANON_SESSION_IP_PER_DAY = bounded_env_int("ANON_SESSION_IP_PER_DAY", 30, 1, 10000)
ANON_CONVERSATIONS_PER_IDENTITY = bounded_env_int("ANON_CONVERSATIONS_PER_IDENTITY", 20, 1, 1000)
ANON_MESSAGES_PER_IDENTITY = bounded_env_int("ANON_MESSAGES_PER_IDENTITY", 500, 1, 10000)
ANON_TEXT_CHARS_PER_IDENTITY = bounded_env_int("ANON_TEXT_CHARS_PER_IDENTITY", 250000, 1000, 10000000)
ANON_CONVERSATIONS_GLOBAL = bounded_env_int("ANON_CONVERSATIONS_GLOBAL", 100000, 100, 10000000)
ANON_MESSAGES_GLOBAL = bounded_env_int("ANON_MESSAGES_GLOBAL", 1000000, 1000, 100000000)
ANON_TEXT_CHARS_GLOBAL = bounded_env_int("ANON_TEXT_CHARS_GLOBAL", 500000000, 100000, 100000000000)
ANON_CONVERSATIONS_IP_PER_DAY = bounded_env_int("ANON_CONVERSATIONS_IP_PER_DAY", 100, 1, 10000)
ANON_MESSAGES_IP_PER_DAY = bounded_env_int("ANON_MESSAGES_IP_PER_DAY", 1000, 1, 100000)
ANON_CONVERSATIONS_GLOBAL_PER_DAY = bounded_env_int("ANON_CONVERSATIONS_GLOBAL_PER_DAY", 10000, 1, 1000000)
ANON_MESSAGES_GLOBAL_PER_DAY = bounded_env_int("ANON_MESSAGES_GLOBAL_PER_DAY", 50000, 1, 10000000)
ANON_SESSION_RETENTION_DAYS = bounded_env_int("ANON_SESSION_RETENTION_DAYS", 90, 30, 3650)
AUTH_RETENTION_DAYS = bounded_env_int("AUTH_RETENTION_DAYS", 30, 7, 365)
EMAIL_TOKEN_RETENTION_DAYS = bounded_env_int("EMAIL_TOKEN_RETENTION_DAYS", 7, 1, 90)
SECURITY_RATE_BUCKET_MAX_ROWS = bounded_env_int("SECURITY_RATE_BUCKET_MAX_ROWS", 50000, 1000, 1000000)
GOOGLE_START_IP_PER_5M = bounded_env_int("GOOGLE_START_IP_PER_5M", 20, 1, 500)
GOOGLE_START_GLOBAL_PER_5M = bounded_env_int("GOOGLE_START_GLOBAL_PER_5M", 500, 10, 100000)

_research_enabled_raw = os.getenv("GENESIS_RESEARCH_ENABLED", "0").strip().lower()
if _research_enabled_raw not in {"0", "1", "false", "true", "no", "yes"}:
    raise RuntimeError("GENESIS_RESEARCH_ENABLED must be a boolean value.")
GENESIS_RESEARCH_ENABLED = _research_enabled_raw in {"1", "true", "yes"}
_research_operators_raw = os.getenv("GENESIS_RESEARCH_OPERATOR_ACCOUNT_IDS", "")
try:
    RESEARCH_OPERATOR_ACCOUNT_IDS = frozenset(str(uuid.UUID(x.strip())) for x in _research_operators_raw.split(",") if x.strip())
except ValueError as exc:
    raise RuntimeError("GENESIS_RESEARCH_OPERATOR_ACCOUNT_IDS must contain UUID account IDs.") from exc
if GENESIS_RESEARCH_ENABLED and not RESEARCH_OPERATOR_ACCOUNT_IDS:
    raise RuntimeError("Research cannot be enabled without an explicit operator account allowlist.")
RESEARCH_GLOBAL_RUNS_PER_DAY = bounded_env_int("RESEARCH_GLOBAL_RUNS_PER_DAY", 20, 1, 1000)
RESEARCH_OPERATOR_RUNS_PER_DAY = bounded_env_int("RESEARCH_OPERATOR_RUNS_PER_DAY", 3, 1, 100)
RESEARCH_GLOBAL_CONCURRENCY = bounded_env_int("RESEARCH_GLOBAL_CONCURRENCY", 1, 1, 10)
RESEARCH_OPERATOR_CONCURRENCY = bounded_env_int("RESEARCH_OPERATOR_CONCURRENCY", 1, 1, 5)


CLOUD_MAX_REQUESTS_PER_DAY = bounded_env_int("CLOUD_MAX_REQUESTS_PER_DAY", 10, 1, 100)
CLOUD_MAX_REQUESTS_PER_IDENTITY_PER_DAY = bounded_env_int("CLOUD_MAX_REQUESTS_PER_IDENTITY_PER_DAY", 10, 1, 100)
CLOUD_MAX_REQUESTS_PER_IP_PER_DAY = bounded_env_int("CLOUD_MAX_REQUESTS_PER_IP_PER_DAY", 30, 1, 1000)
CLOUD_MAX_CONCURRENT_PER_IP = bounded_env_int("CLOUD_MAX_CONCURRENT_PER_IP", 3, 1, 50)
CLOUD_MAX_INPUT_CHARS = bounded_env_int("CLOUD_MAX_INPUT_CHARS", 4000, 1, 8000)
CLOUD_MAX_OUTPUT_TOKENS = bounded_env_int("CLOUD_MAX_OUTPUT_TOKENS", 256, 1, 512)
CLOUD_MAX_DAILY_SPEND_USD = float(os.getenv("CLOUD_MAX_DAILY_SPEND_USD", "1.00"))
CLOUD_MAX_IDENTITY_DAILY_SPEND_USD = float(os.getenv("CLOUD_MAX_IDENTITY_DAILY_SPEND_USD", "0.25"))
CLOUD_MAX_IP_DAILY_SPEND_USD = float(os.getenv("CLOUD_MAX_IP_DAILY_SPEND_USD", "0.50"))
# Configurable upper-bound rates used for reservations. Operators must verify these
# against current model pricing and configure higher values if uncertain.
CLOUD_INPUT_USD_PER_MILLION_TOKENS = float(os.getenv("CLOUD_INPUT_USD_PER_MILLION_TOKENS", "20"))
CLOUD_OUTPUT_USD_PER_MILLION_TOKENS = float(os.getenv("CLOUD_OUTPUT_USD_PER_MILLION_TOKENS", "100"))
CLOUD_PRICING_VERSION = os.getenv("CLOUD_PRICING_VERSION", "local-assumption-v1").strip()
CLOUD_PRICING_MODEL = os.getenv("CLOUD_PRICING_MODEL", os.getenv("OPENAI_MODEL", "gpt-6-luna")).strip()
CLOUD_MAX_CONCURRENT_REQUESTS = bounded_env_int("CLOUD_MAX_CONCURRENT_REQUESTS", 1, 1, 20)
CLOUD_MAX_CONCURRENT_PER_IDENTITY = bounded_env_int("CLOUD_MAX_CONCURRENT_PER_IDENTITY", 1, 1, 5)
CLOUD_TIMEOUT_SECONDS = bounded_env_int("CLOUD_TIMEOUT_SECONDS", 45, 5, 60)
CLOUD_CONTEXT_MAX_TURNS = bounded_env_int("CLOUD_CONTEXT_MAX_TURNS", 6, 0, 20)
CLOUD_CONTEXT_TOKEN_BUDGET = bounded_env_int("CLOUD_CONTEXT_TOKEN_BUDGET", 1200, 0, 8192)
IMAGE_GENERATION_ENABLED = os.getenv("IMAGE_GENERATION_ENABLED", "0").strip().lower() in {"1", "true", "yes"}
IMAGE_ACCOUNT_AUTHORIZATION_ENABLED = os.getenv("IMAGE_ACCOUNT_AUTHORIZATION_ENABLED", "0").strip().lower() in {"1", "true", "yes"}
IMAGE_CLOUD_ENABLED = os.getenv("CLOUD_PROVIDER_ENABLED", "0").strip().lower() in {"1", "true", "yes"}
if DATABASE_BACKEND == "postgresql" and IMAGE_GENERATION_ENABLED and IMAGE_ACCOUNT_AUTHORIZATION_ENABLED and IMAGE_CLOUD_ENABLED:
    raise RuntimeError("Image generation is not enabled for PostgreSQL until its metadata store is migrated and verified.")
OPENAI_IMAGE_MODEL = os.getenv("OPENAI_IMAGE_MODEL", "gpt-image-2.6-flare").strip()
IMAGE_DAILY_REQUEST_LIMIT = bounded_env_int("IMAGE_DAILY_REQUEST_LIMIT", 3, 1, 20)
IMAGE_TIMEOUT_SECONDS = bounded_env_int("IMAGE_TIMEOUT_SECONDS", 90, 10, 180)
IMAGE_STORAGE_MAX_BYTES = bounded_env_int("IMAGE_STORAGE_MAX_MB", 500, 50, 5000) * 1024 * 1024
if not all(0 < x < 1_000_000 for x in (CLOUD_MAX_DAILY_SPEND_USD,
        CLOUD_MAX_IDENTITY_DAILY_SPEND_USD, CLOUD_MAX_IP_DAILY_SPEND_USD, CLOUD_INPUT_USD_PER_MILLION_TOKENS,
        CLOUD_OUTPUT_USD_PER_MILLION_TOKENS)):
    raise RuntimeError("Cloud spend limits and token rates must be positive finite amounts.")
if not CLOUD_PRICING_VERSION or len(CLOUD_PRICING_VERSION) > 80 or not CLOUD_PRICING_MODEL:
    raise RuntimeError("Cloud pricing version and model must be configured.")


def _request_host(authority: str) -> str | None:
    try:
        if not authority or any(char in authority for char in "\\/@?#"):
            return None
        parsed = urlsplit("//" + authority)
        if not parsed.hostname or parsed.username or parsed.password or parsed.path:
            return None
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return None
        return parsed.hostname.rstrip(".").lower()
    except ValueError:
        return None


def _host_allowed(host: str) -> bool:
    host = host.rstrip(".").lower()
    for allowed in TRUSTED_HOSTS:
        rule = allowed.rstrip(".").lower()
        if rule.startswith("*."):
            suffix = rule[1:]
            if host.endswith(suffix) and host != suffix[1:]:
                return True
        elif hmac.compare_digest(host, rule):
            return True
    return False


if CANONICAL_ORIGIN and not _host_allowed((_origin_parts.hostname or "").lower()):
    raise RuntimeError("GENESIS_CANONICAL_ORIGIN host must be present in GENESIS_ALLOWED_HOSTS.")


def _peer_ip(request: Request) -> str:
    value = request.client.host if request.client else ""
    if GENESIS_ENV == "test" and value == "testclient":
        return "127.0.0.1"
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return "unknown"


def _trusted_proxy(peer_ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(peer_ip)
        return any(parsed in network for network in TRUSTED_PROXY_NETWORKS)
    except ValueError:
        return False


def security_event(event: str, *, account_id: str | None = None, ip: str | None = None) -> None:
    """Log only fixed event codes and keyed references; never prompts or raw identifiers."""
    def reference(kind: str, value: str | None) -> str | None:
        if not value:
            return None
        return hmac.new(SECURITY_EVENT_HMAC_SECRET, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:20]
    payload = {"event": event, "account_ref": reference("account", account_id),
        "ip_ref": reference("ip", ip), "time": now()}
    SECURITY_LOGGER.warning("security_event %s", json.dumps(payload, separators=(",", ":")))
    hook = getattr(app.state, "security_alert_hook", None) if "app" in globals() else None
    if callable(hook):
        try:
            hook(dict(payload))
        except Exception:
            SECURITY_LOGGER.error("security_alert_hook_failed")


def security_bucket_hash(category: str, value: str) -> str:
    return hmac.new(ABUSE_HMAC_SECRET, f"marina-security-quota:{category}:{value}".encode(), hashlib.sha256).hexdigest()


def take_security_rate_limit(db: sqlite3.Connection, *, category: str, value: str,
                             limit: int, window_seconds: int,
                             now_dt: datetime | None = None) -> bool:
    """Atomic, cross-worker fixed-window limiter. Caller holds BEGIN IMMEDIATE."""
    moment = now_dt or datetime.now(timezone.utc)
    stamp = moment.isoformat()
    bucket = security_bucket_hash(category, value)
    row = db.execute("SELECT window_started_at,attempts FROM security_rate_limits WHERE bucket_hash=?", (bucket,)).fetchone()
    if row is None:
        # Bound unique-IP churn; stale bucket cleanup is itself bounded.
        cutoff = (moment - timedelta(days=14)).isoformat()
        db.execute("DELETE FROM security_rate_limits WHERE bucket_hash IN (SELECT bucket_hash FROM security_rate_limits WHERE updated_at<? LIMIT 500)", (cutoff,))
        if db.execute("SELECT COUNT(*) FROM security_rate_limits").fetchone()[0] >= SECURITY_RATE_BUCKET_MAX_ROWS:
            return False
        db.execute("INSERT INTO security_rate_limits(bucket_hash,category,window_started_at,attempts,updated_at) VALUES(?,?,?,1,?)",
            (bucket, category, stamp, stamp))
        return True
    started = datetime.fromisoformat(row["window_started_at"])
    if moment >= started + timedelta(seconds=window_seconds):
        db.execute("UPDATE security_rate_limits SET window_started_at=?,attempts=1,updated_at=? WHERE bucket_hash=?",
            (stamp, stamp, bucket))
        return True
    if int(row["attempts"]) >= limit:
        return False
    db.execute("UPDATE security_rate_limits SET attempts=attempts+1,updated_at=? WHERE bucket_hash=?", (stamp, bucket))
    return True


def cleanup_auth_retention(db: sqlite3.Connection, *, now_dt: datetime | None = None, limit: int = 250) -> None:
    """Bounded pruning; active sessions and ownerless/legacy content are untouched."""
    moment = now_dt or datetime.now(timezone.utc)
    stamp = moment.isoformat()
    session_cutoff = (moment - timedelta(days=AUTH_RETENTION_DAYS)).isoformat()
    token_cutoff = (moment - timedelta(days=EMAIL_TOKEN_RETENTION_DAYS)).isoformat()
    anon_cutoff = (moment - timedelta(days=ANON_SESSION_RETENTION_DAYS)).isoformat()
    db.execute("DELETE FROM auth_sessions WHERE token_hash IN (SELECT token_hash FROM auth_sessions WHERE (revoked_at IS NOT NULL AND revoked_at<?) OR (idle_expires_at<? AND absolute_expires_at<?) LIMIT ?)",
        (session_cutoff, session_cutoff, session_cutoff, limit))
    db.execute("DELETE FROM email_action_tokens WHERE token_hash IN (SELECT token_hash FROM email_action_tokens WHERE (consumed_at IS NOT NULL AND consumed_at<?) OR (expires_at<?) LIMIT ?)",
        (token_cutoff, token_cutoff, limit))
    db.execute("DELETE FROM user_sessions WHERE token_hash IN (SELECT token_hash FROM user_sessions WHERE expires_at<? LIMIT ?)",
        (anon_cutoff, limit))
    db.execute("DELETE FROM oauth_transactions WHERE state_hash IN (SELECT state_hash FROM oauth_transactions WHERE expires_at<? OR consumed_at IS NOT NULL LIMIT ?)",
        (stamp, limit))


def check_anonymous_storage_quota(db: sqlite3.Connection, owner_id: str, *,
                                  conversations: int = 0, messages: int = 0,
                                  text_chars: int = 0) -> bool:
    owner = db.execute("SELECT conversation_count,message_count,text_chars FROM anonymous_storage_usage WHERE owner_id=?", (owner_id,)).fetchone()
    current = tuple(int(x) for x in owner) if owner else (0, 0, 0)
    global_row = db.execute("SELECT conversation_count,message_count,text_chars FROM anonymous_storage_global WHERE id=1").fetchone()
    global_current = tuple(int(x) for x in global_row)
    return (current[0] + conversations <= ANON_CONVERSATIONS_PER_IDENTITY
        and current[1] + messages <= ANON_MESSAGES_PER_IDENTITY
        and current[2] + text_chars <= ANON_TEXT_CHARS_PER_IDENTITY
        and global_current[0] + conversations <= ANON_CONVERSATIONS_GLOBAL
        and global_current[1] + messages <= ANON_MESSAGES_GLOBAL
        and global_current[2] + text_chars <= ANON_TEXT_CHARS_GLOBAL)


def take_anonymous_rate_pair(db: sqlite3.Connection, *, category: str, client_ip: str,
                             ip_limit: int, global_limit: int) -> bool:
    now_dt = datetime.now(timezone.utc)
    global_ok = take_security_rate_limit(db, category=f"{category}_global", value="global",
        limit=global_limit, window_seconds=86400, now_dt=now_dt)
    ip_ok = take_security_rate_limit(db, category=f"{category}_ip", value=client_ip,
        limit=ip_limit, window_seconds=86400, now_dt=now_dt)
    return global_ok and ip_ok


def release_durable_operation_lease(lease_id: str | None) -> None:
    if not lease_id:
        return
    with connect_db() as db:
        db.execute("DELETE FROM security_operation_leases WHERE lease_id=?", (lease_id,))


def admit_research_run(operator_id: str) -> str | None:
    now_dt = datetime.now(timezone.utc)
    stamp = now_dt.isoformat()
    expires = (now_dt + timedelta(seconds=180)).isoformat()
    principal_hash = security_bucket_hash("research_principal", operator_id)
    lease_id = str(uuid.uuid4())
    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        cleanup_auth_retention(db, now_dt=now_dt, limit=100)
        db.execute("DELETE FROM security_operation_leases WHERE lease_id IN (SELECT lease_id FROM security_operation_leases WHERE expires_at<=? LIMIT 250)", (stamp,))
        allowed = (take_security_rate_limit(db, category="research_global_daily", value="global",
                limit=RESEARCH_GLOBAL_RUNS_PER_DAY, window_seconds=86400, now_dt=now_dt)
            and take_security_rate_limit(db, category="research_operator_daily", value=operator_id,
                limit=RESEARCH_OPERATOR_RUNS_PER_DAY, window_seconds=86400, now_dt=now_dt))
        if not allowed:
            return None
        global_count = db.execute("SELECT COUNT(*) FROM security_operation_leases WHERE operation='research' AND expires_at>?", (stamp,)).fetchone()[0]
        operator_count = db.execute("SELECT COUNT(*) FROM security_operation_leases WHERE operation='research' AND principal_hash=? AND expires_at>?",
            (principal_hash, stamp)).fetchone()[0]
        if global_count >= RESEARCH_GLOBAL_CONCURRENCY or operator_count >= RESEARCH_OPERATOR_CONCURRENCY:
            return None
        db.execute("INSERT INTO security_operation_leases(lease_id,operation,principal_hash,expires_at,created_at) VALUES(?,?,?,?,?)",
            (lease_id, "research", principal_hash, expires, stamp))
    return lease_id


def _anonymous_identity_path(path: str) -> bool:
    return (path == "/api/chat" or path == "/api/conversations" or path.startswith("/api/conversations/")
        or path in {"/api/preferences", "/api/memories"} or path.startswith("/api/memories/")
        or path.startswith("/api/images/"))


def _new_anonymous_owner(db: sqlite3.Connection, client_ip: str, raw_cookie: str) -> tuple[str | None, bool]:
    """Reserve global/IP issuance quota and persist the new opaque identity atomically."""
    now_dt = datetime.now(timezone.utc)
    cleanup_auth_retention(db, now_dt=now_dt, limit=250)
    admitted = (take_security_rate_limit(db, category="anonymous_session_global", value="global",
                    limit=ANON_SESSION_GLOBAL_PER_DAY, window_seconds=86400, now_dt=now_dt)
        and take_security_rate_limit(db, category="anonymous_session_ip", value=client_ip,
                    limit=ANON_SESSION_IP_PER_DAY, window_seconds=86400, now_dt=now_dt))
    if not admitted:
        return None, False
    owner_id = str(uuid.uuid4())
    expiry = (now_dt + timedelta(days=30)).isoformat()
    db.execute("INSERT INTO user_sessions(token_hash,owner_id,expires_at,created_at) VALUES(?,?,?,?)",
        (hashlib.sha256(raw_cookie.encode()).hexdigest(), owner_id, expiry, now_dt.isoformat()))
    return owner_id, True


def _security_headers(response: Response, request: Request, *, public_scheme: str) -> None:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
    if public_scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if request.url.path.startswith(("/api/", "/auth/")):
        response.headers["Cache-Control"] = "no-store"


def _security_error(request: Request, detail: str, status_code: int, *, scheme: str | None = None) -> JSONResponse:
    response = JSONResponse({"detail": detail}, status_code=status_code)
    _security_headers(response, request, public_scheme=scheme or request.url.scheme.lower())
    return response

provider: AIProvider = OllamaProvider(OLLAMA_URL)
cloud_provider = OpenAIResponsesProvider(max_input_chars=CLOUD_MAX_INPUT_CHARS,
    max_output_tokens=CLOUD_MAX_OUTPUT_TOKENS, timeout_seconds=CLOUD_TIMEOUT_SECONDS,
    max_context_tokens=CLOUD_CONTEXT_TOKEN_BUDGET)
research_adapter = ZeroGenesisResearchAdapter()
image_service = ImageGenerationService(api_key=os.getenv("OPENAI_API_KEY", ""),
    enabled=IMAGE_GENERATION_ENABLED and IMAGE_CLOUD_ENABLED and IMAGE_ACCOUNT_AUTHORIZATION_ENABLED,
    model=OPENAI_IMAGE_MODEL, project_root=ROOT, research_root=research_adapter.root,
    daily_request_limit=IMAGE_DAILY_REQUEST_LIMIT, timeout_seconds=IMAGE_TIMEOUT_SECONDS,
    max_storage_bytes=IMAGE_STORAGE_MAX_BYTES)
_image_csrf_token = secrets.token_urlsafe(32)
_inference_slot = asyncio.Semaphore(1)
_heavy_resource_gate = asyncio.Lock()
_research_active = False
_queue_lock = asyncio.Lock()
_waiting_requests = 0


@contextmanager
def connect_db():
    if DATABASE_BACKEND == "postgresql":
        with postgres_connection() as db:
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
        return
    target = validate_test_database_path(DB_PATH, environment=GENESIS_ENV, project_root=ROOT)
    target.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(target, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    if DATABASE_BACKEND == "postgresql":
        from migrations.postgres import migrate_fresh
        migrate_fresh()
        return
    app_path = validate_test_database_path(DB_PATH, environment=GENESIS_ENV, project_root=ROOT)
    budget_path = validate_test_database_path(cloud_budget_database_path(), environment=GENESIS_ENV, project_root=ROOT)
    migrate_database(app_path)
    if not same_database_path(app_path, budget_path):
        migrate_database(budget_path, migrations=CLOUD_BUDGET_MIGRATIONS)


def same_database_path(first: str | Path, second: str | Path) -> bool:
    return Path(first).expanduser().resolve() == Path(second).expanduser().resolve()


def cloud_budget_database_path() -> Path:
    configured = Path(CLOUD_BUDGET_DB_PATH)
    if (_CLOUD_BUDGET_PATH_WAS_DEFAULTED
            and same_database_path(configured, _CLOUD_BUDGET_IMPORT_DEFAULT)):
        return Path(DB_PATH)
    return configured


def connect_cloud_budget_db() -> sqlite3.Connection:
    """Open an already migrated budget DB without creating a missing file."""
    if DATABASE_BACKEND == "postgresql":
        return checkout_postgres()
    target = validate_test_database_path(cloud_budget_database_path(), environment=GENESIS_ENV, project_root=ROOT)
    if not target.is_file():
        raise sqlite3.OperationalError("Cloud budget database is unavailable.")
    db = sqlite3.connect(target.as_uri() + "?mode=rw", uri=True, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def verify_production_database_ready(path: str | Path | None = None) -> dict:
    """Read-only production startup gate; production migrations are operator-run."""
    if DATABASE_BACKEND == "postgresql":
        if path is not None:
            raise RuntimeError("PostgreSQL readiness does not accept a filesystem path override.")
        try:
            from migrations.postgres import verify_ready
            return verify_ready()
        except Exception as exc:
            raise RuntimeError("Production startup refused: PostgreSQL schema is not ready.") from exc
    target = Path(path) if path is not None else DB_PATH
    try:
        status = inspect_migration_database(target)
    except (MigrationError, OSError, sqlite3.Error) as exc:
        raise RuntimeError("Production startup refused: database cannot be safely inspected; use the approved backup and migration procedure.") from exc
    if status["pending"]:
        raise RuntimeError("Production startup refused: pending schema migrations; review a verified backup and apply migrations through the approved operator procedure.")
    if status["integrity_check"] != "ok" or status["foreign_key_violations"]:
        raise RuntimeError("Production startup refused: database integrity or foreign-key validation failed.")
    # A path override is an isolated verification target: unless it is the
    # configured application path, treat its budget tables as colocated there.
    budget_path = cloud_budget_database_path() if path is None or same_database_path(path, DB_PATH) else target
    if not same_database_path(target, budget_path):
        try:
            budget_status = inspect_migration_database(budget_path, migrations=CLOUD_BUDGET_MIGRATIONS)
        except (MigrationError, OSError, sqlite3.Error) as exc:
            raise RuntimeError("Production startup refused: separate cloud budget database is not ready; use the approved backup and migration procedure.") from exc
        if budget_status["pending"] or budget_status["integrity_check"] != "ok" or budget_status["foreign_key_violations"]:
            raise RuntimeError("Production startup refused: separate cloud budget database has pending migrations or failed integrity checks.")
        try:
            verify_cloud_budget_schema(budget_path)
        except RuntimeError as exc:
            raise RuntimeError("Production startup refused: separate cloud budget database schema is incomplete.") from exc
    else:
        try:
            verify_cloud_budget_schema(target)
        except RuntimeError as exc:
            raise RuntimeError("Production startup refused: cloud budget schema is incomplete.") from exc
    return status


def verify_cloud_budget_schema(path: str | Path) -> None:
    expected = {
        "cloud_budget_daily": {"usage_date", "scope_id", "requests", "reserved_usd", "actual_usd"},
        "cloud_budget_reservations": {"id", "usage_date", "owner_id", "reserved_usd", "status", "created_at",
            "ip_scope_id", "input_rate", "output_rate", "pricing_version", "pricing_model"},
        "cloud_active_requests": {"id", "owner_id", "expires_at", "ip_scope_id"},
    }
    try:
        target = Path(path).expanduser().resolve()
        if not target.is_file():
            raise sqlite3.OperationalError("database missing")
        db = sqlite3.connect(target.as_uri() + "?mode=ro", uri=True, timeout=10)
        try:
            for table, required in expected.items():
                columns = {row[1] for row in db.execute(f'PRAGMA table_info("{table}")')}
                if not required.issubset(columns):
                    raise RuntimeError("Cloud budget schema is incomplete.")
        finally:
            db.close()
    except (OSError, sqlite3.Error) as exc:
        raise RuntimeError("Cloud budget schema is unavailable or invalid.") from exc


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        if GENESIS_ENV == "production":
            # Never mutate a data-bearing database as a side effect of service startup.
            verify_production_database_ready()
        else:
            init_db()
        yield
    finally:
        if DATABASE_BACKEND == "postgresql":
            close_postgres_pool()


class RawBodySizeLimitMiddleware:
    """Bound actual received bytes regardless of Content-Length or transfer encoding."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        limit = MAX_CHAT_BODY_BYTES if path == "/api/chat" else MAX_API_BODY_BYTES
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        declared = headers.get(b"content-length")
        if declared:
            try:
                if int(declared) > limit:
                    return await self._too_large(send, secure=scope.get("scheme") == "https")
            except ValueError:
                await send({"type": "http.response.start", "status": 400, "headers": self._error_headers(secure=scope.get("scheme") == "https")})
                await send({"type": "http.response.body", "body": b'{"detail":"Invalid Content-Length."}'})
                return
        messages, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > limit:
                    return await self._too_large(send, secure=scope.get("scheme") == "https")
                messages.append(message)
                if not message.get("more_body", False):
                    break
        async def replay():
            if messages:
                return messages.pop(0)
            return await receive()
        await self.app(scope, replay, send)

    @staticmethod
    def _error_headers(*, secure: bool) -> list[tuple[bytes, bytes]]:
        rows = [(b"content-type", b"application/json"), (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"strict-origin-when-cross-origin"),
            (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")]
        if secure:
            rows.append((b"strict-transport-security", b"max-age=31536000"))
        return rows

    @classmethod
    async def _too_large(cls, send, *, secure: bool):
        body = b'{"detail":"Request body is too large."}'
        headers = cls._error_headers(secure=secure) + [(b"content-length", str(len(body)).encode())]
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": body})


app = FastAPI(title="GENESIS AI PUBLIC", version="0.2.0", lifespan=lifespan,
    docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(CORSMiddleware, allow_origins=list(CORS_ALLOWED_ORIGINS),
    allow_credentials=True, allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Marina-CSRF", "X-Genesis-Image-Token"], max_age=600)
app.add_middleware(RawBodySizeLimitMiddleware)
from auth_routes import CallbackQueryRedactionMiddleware, router as auth_router
from email_auth import router as email_auth_router
app.include_router(auth_router)
app.include_router(email_auth_router)
app.add_middleware(CallbackQueryRedactionMiddleware)


@app.middleware("http")
async def bind_session_identity(request: Request, call_next):
    host_header = request.headers.get("host", "")
    host = _request_host(host_header)
    if not host or not _host_allowed(host):
        security_event("host_rejected", ip=_peer_ip(request))
        return _security_error(request, "Request host is not allowed.", 400)

    peer_ip = _peer_ip(request)
    if GENESIS_ENV != "production":
        try:
            is_loopback_peer = peer_ip == "testclient" and GENESIS_ENV == "test"
            if not is_loopback_peer and not ipaddress.ip_address(peer_ip).is_loopback:
                security_event("non_loopback_development_peer", ip=peer_ip)
                return _security_error(request, "Non-loopback access requires production configuration.", 403)
        except ValueError:
            return _security_error(request, "Client network address is unavailable.", 403)
    forwarded_names = ("forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port")
    forwarded_present = any(request.headers.get(name) is not None for name in forwarded_names)
    public_host, public_scheme = host_header, request.url.scheme.lower()
    client_ip = peer_ip
    if forwarded_present:
        if request.headers.get("forwarded") is not None or not _trusted_proxy(peer_ip):
            security_event("untrusted_forwarded_headers", ip=peer_ip)
            return _security_error(request, "Forwarded headers are not accepted from this peer.", 400)
        forwarded_for = request.headers.get("x-forwarded-for", "")
        forwarded_host = request.headers.get("x-forwarded-host", "")
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        forwarded_port = request.headers.get("x-forwarded-port")
        # The configured proxy must overwrite these headers with exactly one value;
        # comma chains and competing port fields are ambiguous and rejected.
        if (not forwarded_for or not forwarded_host or not forwarded_proto
                or any("," in value for value in (forwarded_for, forwarded_host, forwarded_proto))
                or forwarded_port is not None or forwarded_proto.lower() not in {"http", "https"}):
            security_event("malformed_forwarded_headers", ip=peer_ip)
            return _security_error(request, "Forwarded headers are malformed.", 400)
        if forwarded_host:
            forwarded_hostname = _request_host(forwarded_host)
            if not forwarded_hostname or not _host_allowed(forwarded_hostname):
                security_event("forwarded_host_rejected", ip=peer_ip)
                return _security_error(request, "Forwarded host is not allowed.", 400)
            public_host = forwarded_host
        if forwarded_proto:
            public_scheme = forwarded_proto.lower()
        if forwarded_for:
            try:
                client_ip = ipaddress.ip_address(forwarded_for.strip()).compressed
            except ValueError:
                security_event("forwarded_client_ip_rejected", ip=peer_ip)
                return _security_error(request, "Forwarded client address is invalid.", 400)
    request.state.client_ip = client_ip
    public_origin = f"{public_scheme}://{public_host}".rstrip("/")
    if CANONICAL_ORIGIN and not hmac.compare_digest(public_origin.lower(), CANONICAL_ORIGIN.lower()):
        security_event("canonical_origin_mismatch", ip=client_ip)
        return _security_error(request, "Request origin is not canonical.", 400, scheme=public_scheme)
    request.state.public_origin = CANONICAL_ORIGIN or public_origin
    origin = request.headers.get("origin")
    if origin and not hmac.compare_digest(origin.rstrip("/").lower(), request.state.public_origin.lower()):
        security_event("origin_rejected", ip=client_ip)
        return _security_error(request, "Cross-origin request rejected.", 403, scheme=public_scheme)

    if request.url.path.startswith("/api/") and any(key in request.query_params for key in ("account_id", "owner_id")):
        return _security_error(request, "Ownership identifiers are server-assigned.", 422, scheme=public_scheme)
    # Enforce same-origin browser mutations before creating or touching identity rows.
    if request.url.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if origin and not hmac.compare_digest(origin.rstrip("/").lower(), request.state.public_origin.lower()):
            return _security_error(request, "Cross-origin request rejected.", 403, scheme=public_scheme)
    # Resolve account identity before issuing an anonymous principal. Authenticated
    # devices must not consume or create anonymous rows.
    try:
        from auth_routes import _session
        account_session = _session(request)
    except Exception:
        account_session = None
    # Anonymous identities are created only for data routes that need an owner.
    # Health, static assets, OAuth, and other public reads never persist sessions.
    cookie = request.cookies.get("genesis_session", "")
    token_digest = hashlib.sha256(cookie.encode()).hexdigest() if cookie else ""
    issue_cookie = False
    owner_id = None
    with connect_db() as db:
        row = db.execute("SELECT owner_id,expires_at FROM user_sessions WHERE token_hash=?", (token_digest,)).fetchone() if token_digest else None
        if row and row["expires_at"] > now():
            owner_id = row["owner_id"]
        else:
            if row:
                db.execute("DELETE FROM user_sessions WHERE token_hash=?", (token_digest,))
                db.commit()
            if not account_session and _anonymous_identity_path(request.url.path):
                cookie = secrets.token_urlsafe(32)
                db.execute("BEGIN IMMEDIATE")
                owner_id, issue_cookie = _new_anonymous_owner(db, client_ip, cookie)
                if not owner_id:
                    response = _security_error(request, "Anonymous service capacity is temporarily limited. Try again later.", 429, scheme=public_scheme)
                    response.headers["Retry-After"] = "86400"
                    return response
    request.state.owner_id = owner_id
    # Account identity is derived only from a live server-side auth session.
    # The anonymous principal remains separate and is never used as a fallback
    # when an authenticated session exists (or to resolve account-owned rows).
    request.state.account_id = account_session["account_id"] if account_session else None
    request.state.auth_session = account_session
    if (account_session and request.url.path.startswith("/api/")
            and request.method in {"POST", "PUT", "PATCH", "DELETE"}):
        csrf_cookie = request.cookies.get("__Host-marina_csrf", "")
        csrf_header = request.headers.get("x-marina-csrf", "")
        origin = request.headers.get("origin", "")
        expected_origin = request.state.public_origin
        valid_csrf = bool(origin and hmac.compare_digest(origin.rstrip("/"), expected_origin.rstrip("/"))
            and csrf_cookie and csrf_header
            and hmac.compare_digest(csrf_cookie, csrf_header)
            and hmac.compare_digest(hashlib.sha256(csrf_cookie.encode()).hexdigest(), account_session["csrf_hash"]))
        if not valid_csrf:
            security_event("csrf_rejected", account_id=account_session["account_id"], ip=client_ip)
            return _security_error(request, "Request authorization check failed.", 403, scheme=public_scheme)
    # SameSite=Strict also prevents browsers attaching this cookie cross-site.
    response = await call_next(request)
    if issue_cookie:
        response.set_cookie("genesis_session", cookie, max_age=30 * 86400, httponly=True,
            secure=public_scheme == "https", samesite="strict", path="/")
    _security_headers(response, request, public_scheme=public_scheme)
    return response


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    conversation_id: str | None = None
    message: str = Field(default="", max_length=MAX_MESSAGE_CHARS)
    model: str = Field(default="", max_length=200)
    regenerate: bool = False
    language: Literal["auto", "en", "si"] = "auto"
    response_length: Literal["short", "balanced", "detailed"] = "balanced"
    remember_preferences: bool = False
    use_approved_memories: bool = False
    share_conversation_context: StrictBool = False
    provider: Literal["openai"] = "openai"


class PreferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    consent: bool
    language: Literal["auto", "en", "si"]
    response_length: Literal["short", "balanced", "detailed"]


class MemoryCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    consent: bool
    content: str = Field(min_length=1, max_length=500)


class ImageGenerationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=IMAGE_MAX_PROMPT_CHARS)
    size: Literal["1024x1024", "1536x1024", "1024x1536"] = "1024x1024"
    quality: Literal["low", "medium", "high"] = "low"
    output_format: Literal["png", "webp", "jpeg"] = "png"
    confirm_cloud_cost: StrictBool


def _is_loopback_hostname(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _parse_http_authority(value: str, *, allow_path: bool = False) -> tuple[str, str, int | None] | None:
    try:
        if not value or any(char.isspace() or ord(char) < 0x21 for char in value):
            return None
        parsed = urlsplit(value if "://" in value else f"http://{value}")
        if parsed.scheme not in {"http", "https"} or parsed.username is not None or parsed.password is not None:
            return None
        if not allow_path and (parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            return None
        if allow_path and parsed.fragment:
            return None
        hostname = parsed.hostname
        if not hostname or not _is_loopback_hostname(hostname):
            return None
        port = parsed.port
        if port == 0:
            return None
        return parsed.scheme.lower(), hostname.lower(), port
    except ValueError:
        return None


def _effective_port(scheme: str, port: int | None) -> int:
    return port if port is not None else (443 if scheme == "https" else 80)


def require_image_origin(request: Request, *, require_token: bool) -> None:
    host_header = request.headers.get("host", "")
    if "://" in host_header:
        raise HTTPException(403, "Image actions are available only from the local GENESIS AI origin.")
    host_origin = _parse_http_authority(host_header)
    client_host = request.client.host if request.client else ""
    try:
        client_is_loopback = ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        client_is_loopback = False
    if host_origin is None or not client_is_loopback:
        raise HTTPException(403, "Image actions are available only from the local GENESIS AI origin.")

    request_scheme = request.url.scheme.lower()
    if request_scheme not in {"http", "https"}:
        raise HTTPException(403, "Image request origin check failed.")
    expected_origin = (request_scheme, host_origin[1], _effective_port(request_scheme, host_origin[2]))

    def matches_local_origin(value: str, *, referer: bool) -> bool:
        parsed = _parse_http_authority(value, allow_path=referer)
        if parsed is None:
            return False
        return (parsed[0], parsed[1], _effective_port(parsed[0], parsed[2])) == expected_origin

    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    if require_token and not origin:
        raise HTTPException(403, "Image request origin check failed.")
    if origin and not matches_local_origin(origin, referer=False):
        raise HTTPException(403, "Image request origin check failed.")
    if referer and not matches_local_origin(referer, referer=True):
        raise HTTPException(403, "Image request origin check failed.")
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site and fetch_site != "same-origin":
        raise HTTPException(403, "Image request origin check failed.")
    if require_token:
        supplied = request.headers.get("x-genesis-image-token", "")
        if not hmac.compare_digest(supplied, _image_csrf_token):
            raise HTTPException(403, "Image request authorization check failed.")


@app.get("/api/images/status")
async def image_status(request: Request):
    require_image_origin(request, require_token=False)
    data = image_service.safe_status()
    data["account_access_checked"] = bool(request.state.account_id)
    if not request.state.account_id:
        data["available"] = False
        data["reason"] = "authentication_required"
    data["csrf_token"] = _image_csrf_token
    data["requests_used_today"] = image_service.attempts_today()
    return JSONResponse(data, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


def image_error_response(exc: ImageGenerationError) -> JSONResponse:
    return JSONResponse({"detail": {"code": exc.code, "message": exc.message}},
        status_code=exc.status_code, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@app.post("/api/images/generations")
async def generate_image(request: Request, payload: ImageGenerationRequest):
    require_image_origin(request, require_token=True)
    if not payload.confirm_cloud_cost:
        return image_error_response(ImageGenerationError("confirmation_required",
            "Confirm the cloud request and cost disclosure before generating.", 400))
    if not image_service.ready:
        try:
            await image_service.generate(prompt=payload.prompt, size=payload.size, quality=payload.quality,
                output_format=payload.output_format, confirm_cloud_cost=payload.confirm_cloud_cost,
                account_id=request.state.account_id)
        except ImageGenerationError as exc:
            return image_error_response(exc)
        raise HTTPException(503, "Image generation is unavailable.")
    if _inference_slot.locked() or _waiting_requests or _research_active or _heavy_resource_gate.locked():
        return image_error_response(ImageGenerationError("resource_busy",
            "Another resource-intensive task is active. Try again when it finishes.", 429))
    memory = memory_status()
    if memory.get("available_bytes") is not None and memory["available_bytes"] < LOW_MEMORY_BYTES:
        return image_error_response(ImageGenerationError("low_memory",
            "Image generation is paused because available system memory is low.", 503))
    try:
        async with _heavy_resource_gate:
            if _inference_slot.locked() or _waiting_requests or _research_active:
                return image_error_response(ImageGenerationError("resource_busy",
                    "Another resource-intensive task is active. Try again when it finishes.", 429))
            record = await image_service.generate(prompt=payload.prompt, size=payload.size,
                quality=payload.quality, output_format=payload.output_format,
                confirm_cloud_cost=payload.confirm_cloud_cost, account_id=request.state.account_id)
    except ImageGenerationError as exc:
        return image_error_response(exc)
    return JSONResponse({
        "image_id": record.image_id,
        "preview_url": f"/api/images/{record.image_id}/preview",
        "download_url": f"/api/images/{record.image_id}/download",
        "model": record.model,
        "size": record.size,
        "quality": record.quality,
        "output_format": record.output_format,
        "width": record.width,
        "height": record.height,
        "byte_length": record.byte_length,
        "created_at": record.created_at,
        "estimated_cost_usd": record.estimated_cost_usd,
        "token_usage": record.token_usage,
        "cost_notice": image_service.safe_status()["cost"]["notice"],
    }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


def image_binary_response(image_id: str, *, attachment: bool, account_id: str | None) -> Response:
    try:
        if not account_id:
            raise ImageGenerationError("not_found", "Image not found.", 404)
        record, content = image_service.load_image(image_id, account_id=account_id)
    except ImageGenerationError as exc:
        return image_error_response(exc)
    disposition = "attachment" if attachment else "inline"
    filename = f"genesis-image-{record.image_id}.{record.output_format if record.output_format != 'jpeg' else 'jpg'}"
    return Response(content=content, media_type=record.media_type, headers={
        "Content-Disposition": f'{disposition}; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, no-store",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "X-Frame-Options": "DENY",
    })


@app.get("/api/images/{image_id}/preview")
async def preview_image(image_id: str, request: Request):
    require_image_origin(request, require_token=False)
    return image_binary_response(image_id, attachment=False, account_id=request.state.account_id)


@app.get("/api/images/{image_id}/download")
async def download_image(image_id: str, request: Request):
    require_image_origin(request, require_token=False)
    return image_binary_response(image_id, attachment=True, account_id=request.state.account_id)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def principal(request: Request) -> tuple[str, str]:
    account_id = getattr(request.state, "account_id", None)
    if account_id:
        return "account_id", account_id
    owner_id = getattr(request.state, "owner_id", None)
    if not owner_id:
        raise HTTPException(401, "A valid session is required.")
    return "owner_id", owner_id


def get_conversation(conversation_id: str, owner_id: str, *, ownership_column: str = "owner_id") -> sqlite3.Row:
    if ownership_column not in {"owner_id", "account_id"}:
        raise ValueError("Invalid ownership column")
    with connect_db() as db:
        row = db.execute(f"SELECT * FROM conversations WHERE id=? AND {ownership_column}=?", (conversation_id, owner_id)).fetchone()
    if row is None:
        raise HTTPException(404, "Conversation not found")
    return row


def save_preferences(owner_id: str, language: str, response_length: str, *, ownership_column: str = "owner_id") -> None:
    if ownership_column == "account_id":
        with connect_db() as db:
            db.execute("""INSERT INTO preferences(account_id,language,response_length,consented_at)
                VALUES(?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET language=excluded.language,
                response_length=excluded.response_length,consented_at=excluded.consented_at""",
                (owner_id, language, response_length, now()))
        return
    with connect_db() as db:
        db.execute("INSERT INTO preferences(owner_id,language,response_length,consented_at) VALUES(?,?,?,?) "
            "ON CONFLICT(owner_id) DO UPDATE SET language=excluded.language,response_length=excluded.response_length,consented_at=excluded.consented_at",
            (owner_id, language, response_length, now()))


@app.get("/api/health")
async def health():
    configured = cloud_provider.configured
    memory = memory_status()
    low_memory = memory.get("available_bytes") is not None and memory["available_bytes"] < LOW_MEMORY_BYTES
    return {"status": "configured" if configured else "unavailable", "provider": "openai",
            "model": cloud_provider.model or None, "openai": "configured" if configured else "unavailable",
            "memory": memory, "low_memory": low_memory, "active_inferences": int(_inference_slot.locked()),
            "queued_inferences": _waiting_requests, "research_active": _research_active}


@app.get("/api/models")
async def models(backend: Literal["openai"] = "openai"):
    try:
        names = await cloud_provider.list_models()
        default = cloud_provider.model
        default = default if default in names else (names[0] if names else "")
        return {"provider": backend, "models": names, "default": default}
    except ProviderError as exc:
        raise HTTPException(503, str(exc)) from exc


@app.get("/api/providers")
def provider_status():
    return {"default": "openai", "providers": {
        "openai": {"available": cloud_provider.configured, "enabled": cloud_provider.enabled,
            "credential_configured": bool(cloud_provider.api_key),
            "model_configured": bool(cloud_provider.model), "model": cloud_provider.model or None,
            "label": "OpenAI GPT",
            "daily_request_limit": CLOUD_MAX_REQUESTS_PER_DAY,
            "daily_global_spend_limit_usd": CLOUD_MAX_DAILY_SPEND_USD,
            "daily_identity_spend_limit_usd": CLOUD_MAX_IDENTITY_DAILY_SPEND_USD,
            "daily_identity_request_limit": CLOUD_MAX_REQUESTS_PER_IDENTITY_PER_DAY,
            "input_reservation_rate_usd_per_million": CLOUD_INPUT_USD_PER_MILLION_TOKENS,
            "output_reservation_rate_usd_per_million": CLOUD_OUTPUT_USD_PER_MILLION_TOKENS,
            "max_global_concurrency": CLOUD_MAX_CONCURRENT_REQUESTS,
            "max_identity_concurrency": CLOUD_MAX_CONCURRENT_PER_IDENTITY,
            "max_ip_concurrency": CLOUD_MAX_CONCURRENT_PER_IP,
            "daily_ip_request_limit": CLOUD_MAX_REQUESTS_PER_IP_PER_DAY,
            "max_input_chars": CLOUD_MAX_INPUT_CHARS,
            "max_output_tokens": CLOUD_MAX_OUTPUT_TOKENS,
            "timeout_seconds": CLOUD_TIMEOUT_SECONDS,
            "pricing": {"version": CLOUD_PRICING_VERSION, "model": CLOUD_PRICING_MODEL,
                "input_usd_per_million_tokens": CLOUD_INPUT_USD_PER_MILLION_TOKENS,
                "output_usd_per_million_tokens": CLOUD_OUTPUT_USD_PER_MILLION_TOKENS,
                "notice": "Configured reservation assumptions only; estimates are not a provider billing cap."}}}}

def estimate_request_cost(messages: list[dict[str, str]]) -> tuple[int, float]:
    # UTF-8 bytes bound token count conservatively for supported text inputs;
    # add per-message framing allowance, then reserve the full output-token cap.
    input_tokens = sum(len(item["content"].encode("utf-8")) + 16 for item in messages)
    estimated = (input_tokens * CLOUD_INPUT_USD_PER_MILLION_TOKENS
        + CLOUD_MAX_OUTPUT_TOKENS * CLOUD_OUTPUT_USD_PER_MILLION_TOKENS) / 1_000_000
    return input_tokens, estimated


def _log_postgres_budget_failure(exc: Exception, *, phase: str, operation: str, db) -> None:
    """Emit sanitized diagnostics only for isolated PostgreSQL test runs."""
    if GENESIS_ENV != "test" or DATABASE_BACKEND != "postgresql":
        return
    allowed_phases = {"reservation", "settlement", "rollback"}
    allowed_operations = {
        "checkout", "begin", "expire_leases", "count_active", "read_global_budget",
        "read_identity_budget", "read_ip_budget", "check_limits", "upsert_global_budget",
        "upsert_identity_budget", "upsert_ip_budget", "insert_reservation",
        "insert_active_lease", "settlement_begin", "settlement_read",
        "settlement_write", "settlement_mark_unknown", "rollback",
    }
    if phase not in allowed_phases or operation not in allowed_operations:
        return
    cause = exc.__cause__ or exc
    exception_class = type(cause).__name__
    if not exception_class.isascii() or not exception_class.isalnum() or len(exception_class) > 80:
        exception_class = "DatabaseError"
    sqlstate = getattr(cause, "sqlstate", None)
    if not (isinstance(sqlstate, str) and len(sqlstate) == 5 and sqlstate.isascii() and sqlstate.isalnum()):
        sqlstate = None
    raw = getattr(db, "_raw", None)
    status = getattr(getattr(raw, "info", None), "transaction_status", None)
    status_name = getattr(status, "name", None)
    if status_name not in {"IDLE", "ACTIVE", "INTRANS", "INERROR", "UNKNOWN"}:
        status_name = "UNKNOWN"
    payload = {"event": "postgres_budget_diagnostic", "phase": phase,
        "operation": operation, "exception_class": exception_class,
        "sqlstate": sqlstate, "transaction_state": status_name}
    SECURITY_LOGGER.error("postgres_budget_diagnostic %s", json.dumps(payload, separators=(",", ":")))


_CLOUD_BUDGET_DAILY_UPSERT_SQL = (
    "INSERT INTO cloud_budget_daily AS daily(usage_date,scope_id,requests,reserved_usd,actual_usd) "
    "VALUES(?,?,1,?,0) ON CONFLICT(usage_date,scope_id) DO UPDATE SET "
    "requests=daily.requests+1,reserved_usd=daily.reserved_usd+excluded.reserved_usd"
)


def _ip_budget_scope(ip_address: str | None) -> str | None:
    if not ip_address:
        return None
    try:
        normalized = ipaddress.ip_address(ip_address).compressed
    except ValueError:
        return None
    digest = hmac.new(ABUSE_HMAC_SECRET, normalized.encode("ascii"), hashlib.sha256).hexdigest()
    return "ip:" + digest


def reserve_cloud_request(owner_id: str, messages: list[dict[str, str]], *, ip_address: str | None = None) -> tuple[str | None, str | None]:
    """Atomically reserve daily global/per-identity budget and a shared concurrency lease."""
    ip_scope = _ip_budget_scope(ip_address)
    if ip_scope is None:
        return None, "ip_unavailable"
    usage_date = datetime.now(timezone.utc).date().isoformat()
    _, reserve_usd = estimate_request_cost(messages)
    reservation_id, active_id = str(uuid.uuid4()), str(uuid.uuid4())
    expires = (datetime.now(timezone.utc) + timedelta(seconds=max(180, CLOUD_TIMEOUT_SECONDS * 3))).isoformat()
    db = None
    operation = "checkout"

    def execute(name: str, sql: str, parameters=()):
        nonlocal operation
        operation = name
        return db.execute(sql, parameters)

    def rollback_transaction():
        nonlocal operation
        operation = "rollback"
        try:
            db.rollback()
        except Exception as rollback_exc:
            _log_postgres_budget_failure(rollback_exc, phase="rollback", operation="rollback", db=db)
            raise

    try:
        db = connect_cloud_budget_db()
        execute("begin", "BEGIN IMMEDIATE")
        execute("expire_leases", "DELETE FROM cloud_active_requests WHERE expires_at<=?", (now(),))
        operation = "count_active"
        active_count = execute("count_active", "SELECT COUNT(*) FROM cloud_active_requests").fetchone()[0]
        owner_active = execute("count_active", "SELECT COUNT(*) FROM cloud_active_requests WHERE owner_id=?", (owner_id,)).fetchone()[0]
        ip_active = execute("count_active", "SELECT COUNT(*) FROM cloud_active_requests WHERE ip_scope_id=?", (ip_scope,)).fetchone()[0]
        if (active_count >= CLOUD_MAX_CONCURRENT_REQUESTS or owner_active >= CLOUD_MAX_CONCURRENT_PER_IDENTITY
                or ip_active >= CLOUD_MAX_CONCURRENT_PER_IP):
            rollback_transaction()
            return None, "concurrency"
        global_row = execute("read_global_budget", "SELECT requests,reserved_usd,actual_usd FROM cloud_budget_daily WHERE usage_date=? AND scope_id='global'", (usage_date,)).fetchone()
        owner_row = execute("read_identity_budget", "SELECT requests,reserved_usd,actual_usd FROM cloud_budget_daily WHERE usage_date=? AND scope_id=?", (usage_date, owner_id)).fetchone()
        ip_row = execute("read_ip_budget", "SELECT requests,reserved_usd,actual_usd FROM cloud_budget_daily WHERE usage_date=? AND scope_id=?", (usage_date, ip_scope)).fetchone()
        operation = "check_limits"
        if global_row and global_row[0] >= CLOUD_MAX_REQUESTS_PER_DAY:
            rollback_transaction()
            return None, "global_requests"
        if owner_row and owner_row[0] >= CLOUD_MAX_REQUESTS_PER_IDENTITY_PER_DAY:
            rollback_transaction()
            return None, "identity_requests"
        if ip_row and ip_row[0] >= CLOUD_MAX_REQUESTS_PER_IP_PER_DAY:
            rollback_transaction()
            return None, "ip_requests"
        if (global_row[1] + global_row[2] if global_row else 0) + reserve_usd > CLOUD_MAX_DAILY_SPEND_USD:
            rollback_transaction()
            return None, "global_budget"
        if (owner_row[1] + owner_row[2] if owner_row else 0) + reserve_usd > CLOUD_MAX_IDENTITY_DAILY_SPEND_USD:
            rollback_transaction()
            return None, "identity_budget"
        if (ip_row[1] + ip_row[2] if ip_row else 0) + reserve_usd > CLOUD_MAX_IP_DAILY_SPEND_USD:
            rollback_transaction()
            return None, "ip_budget"
        execute("upsert_global_budget", _CLOUD_BUDGET_DAILY_UPSERT_SQL, (usage_date, "global", reserve_usd))
        execute("upsert_identity_budget", _CLOUD_BUDGET_DAILY_UPSERT_SQL, (usage_date, owner_id, reserve_usd))
        execute("upsert_ip_budget", _CLOUD_BUDGET_DAILY_UPSERT_SQL, (usage_date, ip_scope, reserve_usd))
        execute("insert_reservation", """INSERT INTO cloud_budget_reservations
            (id,usage_date,owner_id,reserved_usd,status,created_at,ip_scope_id,input_rate,output_rate,pricing_version,pricing_model)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (reservation_id, usage_date, owner_id, reserve_usd, "reserved", now(), ip_scope,
             CLOUD_INPUT_USD_PER_MILLION_TOKENS, CLOUD_OUTPUT_USD_PER_MILLION_TOKENS,
             CLOUD_PRICING_VERSION, CLOUD_PRICING_MODEL))
        execute("insert_active_lease", "INSERT INTO cloud_active_requests(id,owner_id,expires_at,ip_scope_id) VALUES(?,?,?,?)",
            (active_id, owner_id, expires, ip_scope))
        db.commit()
        return reservation_id, active_id
    except sqlite3.Error as exc:
        _log_postgres_budget_failure(exc, phase="reservation", operation=operation, db=db)
        if db is not None:
            rollback_transaction()
        return None, "budget_store_unavailable"
    except Exception as exc:
        _log_postgres_budget_failure(exc, phase="reservation", operation=operation, db=db)
        if db is not None:
            rollback_transaction()
        raise
    finally:
        if db is not None:
            db.close()


def reconcile_cloud_reservation(reservation_id: str, usage: dict | None) -> None:
    """Reconcile completed provider usage; unknown outcomes keep the full reservation."""
    db = None
    operation = "checkout"

    def rollback_transaction():
        nonlocal operation
        operation = "rollback"
        try:
            db.rollback()
        except Exception as rollback_exc:
            _log_postgres_budget_failure(rollback_exc, phase="rollback", operation="rollback", db=db)
            raise

    try:
        db = connect_cloud_budget_db()
        operation = "settlement_begin"
        db.execute("BEGIN IMMEDIATE")
        operation = "settlement_read"
        row = db.execute("SELECT usage_date,owner_id,reserved_usd,status,ip_scope_id,input_rate,output_rate,pricing_version,pricing_model FROM cloud_budget_reservations WHERE id=?", (reservation_id,)).fetchone()
        if row is None or row[3] != "reserved":
            rollback_transaction()
            return
        actual = None
        if usage is not None and row[5] is not None and row[6] is not None:
            input_tokens, output_tokens = usage.get("input_tokens"), usage.get("output_tokens")
            if (isinstance(input_tokens, int) and not isinstance(input_tokens, bool) and input_tokens >= 0
                    and isinstance(output_tokens, int) and not isinstance(output_tokens, bool) and output_tokens >= 0):
                actual = (input_tokens * row[5] + output_tokens * row[6]) / 1_000_000
        if actual is None:
            operation = "settlement_mark_unknown"
            db.execute("UPDATE cloud_budget_reservations SET status='unknown' WHERE id=?", (reservation_id,))
            db.commit()
            return
        date, owner_id, reserved, _, ip_scope = row[:5]
        operation = "settlement_write"
        db.execute("UPDATE cloud_budget_daily SET reserved_usd=MAX(0,reserved_usd-?),actual_usd=actual_usd+? WHERE usage_date=? AND scope_id IN ('global',?,?)",
            (reserved, actual, date, owner_id, ip_scope))
        db.execute("UPDATE cloud_budget_reservations SET status='reconciled' WHERE id=?", (reservation_id,))
        db.commit()
    except Exception as exc:
        _log_postgres_budget_failure(exc, phase="settlement", operation=operation, db=db)
        if db is not None:
            rollback_transaction()
        raise
    finally:
        if db is not None:
            db.close()


def cancel_cloud_reservation_before_dispatch(reservation_id: str | None) -> None:
    """Release a reservation only when validation fails before provider dispatch."""
    if not reservation_id:
        return
    db = connect_cloud_budget_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT usage_date,owner_id,reserved_usd,status,ip_scope_id FROM cloud_budget_reservations WHERE id=?", (reservation_id,)).fetchone()
        if row is None or row[3] != "reserved":
            db.rollback()
            return
        date, owner_id, reserved, _, ip_scope = row
        db.execute("UPDATE cloud_budget_daily SET reserved_usd=MAX(0,reserved_usd-?),requests=MAX(0,requests-1) WHERE usage_date=? AND scope_id IN ('global',?,?)",
            (reserved, date, owner_id, ip_scope))
        db.execute("UPDATE cloud_budget_reservations SET status='cancelled_before_dispatch' WHERE id=?", (reservation_id,))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def release_cloud_active_request(active_id: str | None) -> None:
    if not active_id:
        return
    db = connect_cloud_budget_db()
    try:
        db.execute("DELETE FROM cloud_active_requests WHERE id=?", (active_id,))
        db.commit()
    finally:
        db.close()


@app.get("/api/preferences")
def read_preferences(request: Request):
    column, identity = principal(request)
    with connect_db() as db:
        row = db.execute(f"SELECT language,response_length FROM preferences WHERE {column}=?", (identity,)).fetchone()
    return {"saved": bool(row), **(dict(row) if row else {"language": "auto", "response_length": "balanced"})}


@app.put("/api/preferences")
def update_preferences(request: Request, payload: PreferenceRequest):
    if not payload.consent:
        raise HTTPException(400, "Explicit consent is required to save preferences.")
    column, identity = principal(request)
    save_preferences(identity, payload.language, payload.response_length, ownership_column=column)
    return {"saved": True, "language": payload.language, "response_length": payload.response_length}


@app.delete("/api/preferences")
def clear_preferences(request: Request):
    column, identity = principal(request)
    with connect_db() as db:
        db.execute(f"DELETE FROM preferences WHERE {column}=?", (identity,))
    return {"saved": False}


@app.get("/api/memories")
def list_approved_memories(request: Request):
    column, identity = principal(request)
    with connect_db() as db:
        rows = db.execute(f"SELECT id,content,created_at FROM approved_memories WHERE {column}=? ORDER BY id DESC LIMIT 50", (identity,)).fetchall()
    return {"memories": [dict(row) for row in rows]}


@app.post("/api/memories")
def add_approved_memory(request: Request, payload: MemoryCreateRequest):
    if not payload.consent:
        raise HTTPException(400, "Explicit approval is required to save a memory.")
    content = payload.content.strip()
    if not content:
        raise HTTPException(400, "Memory text cannot be blank.")
    column, identity = principal(request)
    with connect_db() as db:
        inserted = db.execute(f"INSERT INTO approved_memories({column},content,created_at) VALUES(?,?,?) RETURNING id", (identity, content, now())).fetchone()
        row = db.execute(f"SELECT id,content,created_at FROM approved_memories WHERE id=? AND {column}=?", (inserted[0], identity)).fetchone()
    return dict(row)


@app.delete("/api/memories/{memory_id}")
def delete_approved_memory(memory_id: int, request: Request):
    column, identity = principal(request)
    with connect_db() as db:
        cur = db.execute(f"DELETE FROM approved_memories WHERE id=? AND {column}=?", (memory_id, identity))
    if cur.rowcount == 0:
        raise HTTPException(404, "Memory not found.")
    return {"deleted": True}


@app.get("/api/conversations")
def conversations(request: Request):
    column, identity = principal(request)
    with connect_db() as db:
        rows = db.execute(f"SELECT id,title,model,created_at,updated_at FROM conversations WHERE {column}=? ORDER BY updated_at DESC", (identity,)).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/conversations")
async def create_conversation(request: Request):
    body = await request.body()
    if body:
        try:
            supplied = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(400, "Invalid conversation request.") from None
        if not isinstance(supplied, dict) or any(key in supplied for key in ("account_id", "owner_id")):
            raise HTTPException(422, "Ownership identifiers are server-assigned.")
    column, identity = principal(request)
    ident, stamp = str(uuid.uuid4()), now()
    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        if column == "owner_id":
            client_ip = getattr(request.state, "client_ip", "unknown")
            allowed = (take_security_rate_limit(db, category="anonymous_conversation_global", value="global",
                            limit=ANON_CONVERSATIONS_GLOBAL_PER_DAY, window_seconds=86400)
                and take_security_rate_limit(db, category="anonymous_conversation_ip", value=client_ip,
                            limit=ANON_CONVERSATIONS_IP_PER_DAY, window_seconds=86400))
            if not allowed or not check_anonymous_storage_quota(db, identity, conversations=1):
                raise HTTPException(429, "Anonymous conversation storage limit reached.")
        retention_class = "account" if column == "account_id" else "anonymous"
        db.execute(f"INSERT INTO conversations(id,title,model,{column},created_at,updated_at,retention_class,last_activity_at) VALUES(?,?,?,?,?,?,?,?)", (ident, "New conversation", cloud_provider.model, identity, stamp, stamp, retention_class, stamp))
    return {"id": ident, "title": "New conversation", "model": cloud_provider.model, "created_at": stamp, "updated_at": stamp}


@app.get("/api/conversations/{conversation_id}")
def conversation_detail(conversation_id: str, request: Request):
    column, identity = principal(request)
    row = get_conversation(conversation_id, identity, ownership_column=column)
    with connect_db() as db:
        messages = db.execute("SELECT id,role,content,created_at FROM messages WHERE conversation_id=? ORDER BY id", (conversation_id,)).fetchall()
    return {"conversation": {key: row[key] for key in ("id", "title", "model", "created_at", "updated_at")},
        "messages": [dict(m) for m in messages]}


@app.delete("/api/conversations/{conversation_id}")
def delete_conversation(conversation_id: str, request: Request):
    column, identity = principal(request)
    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        active = db.execute("SELECT 1 FROM conversation_activity_leases WHERE conversation_id=? AND lease_until>?", (conversation_id, now())).fetchone()
        if active:
            raise HTTPException(409, "Conversation has an active request; try deletion again after it completes.")
        cur = db.execute(f"DELETE FROM conversations WHERE id=? AND {column}=?", (conversation_id, identity))
        if cur.rowcount == 0:
            raise HTTPException(404, "Conversation not found")
        db.execute("INSERT INTO data_deletion_tombstones(object_type,object_id,deleted_at,policy_version) VALUES('conversation',?,?,?) ON CONFLICT(object_type,object_id) DO UPDATE SET deleted_at=excluded.deleted_at,policy_version=excluded.policy_version", (conversation_id, now(), "retention-v1"))
    return {"ok": True}


def emit(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


async def event_stream(request: Request, payload: ChatRequest) -> AsyncIterator[str]:
    global _waiting_requests
    selected_provider = cloud_provider
    ownership_column, owner_id = principal(request)
    if not owner_id:
        yield emit("error", {"message": "Session identity is unavailable; request refused."})
        return
    budget_reservation_id = None
    active_request_id = None
    retention_lease_id = None
    if not cloud_provider.configured:
        yield emit("error", {"message": "GPT chat is unavailable. Check the local OpenAI configuration and try again."})
        return
    conversation_id = payload.conversation_id
    original_text = payload.message.strip()
    if not payload.regenerate and not original_text:
        yield emit("error", {"message": "Write a message before sending."})
        return
    if len(original_text) > MAX_MESSAGE_CHARS:
        yield emit("error", {"message": "Message is too long."})
        return
    if payload.regenerate and not conversation_id:
        yield emit("error", {"message": "Choose a conversation before regenerating."})
        return
    if conversation_id:
        try:
            get_conversation(conversation_id, owner_id, ownership_column=ownership_column)
        except HTTPException:
            yield emit("error", {"message": "Conversation not found."})
            return

    if ownership_column == "owner_id":
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not take_anonymous_rate_pair(db, category="anonymous_chat", client_ip=getattr(request.state, "client_ip", "unknown"),
                    ip_limit=ANON_MESSAGES_IP_PER_DAY, global_limit=ANON_MESSAGES_GLOBAL_PER_DAY):
                yield emit("error", {"message": "Anonymous request limit reached. Try again later."})
                return

    # Image capability requests stay separate from the chat provider.
    if not payload.regenerate and is_image_request(original_text):
        language = detect_language(original_text, payload.language)
        answer = image_unavailable_message(language)
        if conversation_id is None:
            conversation_id, stamp = str(uuid.uuid4()), now()
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            if ownership_column == "owner_id":
                client_ip = getattr(request.state, "client_ip", "unknown")
                limits_ok = True
                if payload.conversation_id is None:
                    limits_ok = take_anonymous_rate_pair(db, category="anonymous_conversation", client_ip=client_ip,
                        ip_limit=ANON_CONVERSATIONS_IP_PER_DAY, global_limit=ANON_CONVERSATIONS_GLOBAL_PER_DAY)
                if payload.conversation_id is None and not check_anonymous_storage_quota(
                        db, owner_id, conversations=1, messages=2, text_chars=len(original_text) + len(answer)):
                    limits_ok = False
                if not take_anonymous_rate_pair(db, category="anonymous_message_write", client_ip=client_ip,
                        ip_limit=ANON_MESSAGES_IP_PER_DAY, global_limit=ANON_MESSAGES_GLOBAL_PER_DAY):
                    limits_ok = False
                if not limits_ok:
                    yield emit("error", {"message": "Anonymous storage limit reached."})
                    return
            if payload.conversation_id is None:
                initial_model = payload.model or cloud_provider.model
                stamp = now()
                retention_class = "account" if ownership_column == "account_id" else "anonymous"
                db.execute(f"INSERT INTO conversations(id,title,model,{ownership_column},created_at,updated_at,retention_class,last_activity_at) VALUES(?,?,?,?,?,?,?,?)", (conversation_id, original_text[:56] or "New conversation", initial_model, owner_id, stamp, stamp, retention_class, stamp))
            db.execute("INSERT INTO messages(conversation_id,role,content,created_at) VALUES(?,?,?,?)", (conversation_id, "user", original_text, now()))
            db.execute("INSERT INTO messages(conversation_id,role,content,created_at) VALUES(?,?,?,?)", (conversation_id, "assistant", answer, now()))
            stamp = now()
            db.execute(f"UPDATE conversations SET updated_at=?,last_activity_at=? WHERE id=? AND {ownership_column}=?", (stamp, stamp, conversation_id, owner_id))
        yield emit("meta", {"conversation_id": conversation_id, "model": payload.model or cloud_provider.model,
            "provider": "openai", "language": language})
        yield emit("token", {"text": answer})
        yield emit("done", {})
        return

    new_conversation = conversation_id is None
    if new_conversation:
        conversation_id = str(uuid.uuid4())

    # One active inference and at most three waiting requests protect 8 GB machines.
    async with _queue_lock:
        if _waiting_requests >= MAX_WAITING_REQUESTS:
            yield emit("error", {"message": "GPT is busy. Try again shortly."})
            return
        _waiting_requests += 1
        queue_position = _waiting_requests
    acquired = False
    resource_acquired = False
    queue_registered = True
    try:
        yield emit("queued", {"position": queue_position})
        try:
            await asyncio.wait_for(_inference_slot.acquire(), timeout=QUEUE_TIMEOUT)
            acquired = True
        except asyncio.TimeoutError:
            yield emit("error", {"message": "Timed out waiting for GPT."})
            return
        finally:
            async with _queue_lock:
                _waiting_requests = max(0, _waiting_requests - 1)
                queue_registered = False
        await _heavy_resource_gate.acquire()
        resource_acquired = True

        mem = memory_status()
        if mem.get("available_bytes") is not None and mem["available_bytes"] < LOW_MEMORY_BYTES:
            yield emit("error", {"message": "Generation paused because system memory is low. Close other apps and retry."})
            return
        if await request.is_disconnected():
            return

        model = payload.model.strip() or cloud_provider.model
        try:
            available = await selected_provider.list_models()
        except ProviderError as exc:
            yield emit("error", {"message": str(exc)})
            return
        if not model:
            model = available[0] if available else ""
        if model not in available:
            yield emit("error", {"message": "Choose an available model for the selected provider."})
            return
        if isinstance(selected_provider, OpenAIResponsesProvider) and model != CLOUD_PRICING_MODEL:
            security_event("pricing_model_mismatch", account_id=owner_id,
                ip=getattr(request.state, "client_ip", None))
            yield emit("error", {"message": "GPT requests are paused because the configured pricing model does not match the active model."})
            return

        regenerate_assistant_id = None
        if payload.regenerate:
            with connect_db() as db:
                latest = db.execute(f"SELECT id,role FROM messages WHERE conversation_id=? AND conversation_id IN (SELECT id FROM conversations WHERE {ownership_column}=?) ORDER BY id DESC LIMIT 1", (conversation_id, owner_id)).fetchone()
                if latest and latest["role"] == "assistant":
                    regenerate_assistant_id = latest["id"]
                last_user = db.execute(f"SELECT content FROM messages WHERE conversation_id=? AND role='user' AND conversation_id IN (SELECT id FROM conversations WHERE {ownership_column}=?) ORDER BY id DESC LIMIT 1", (conversation_id, owner_id)).fetchone()
                if not last_user:
                    yield emit("error", {"message": "There is no message to regenerate."})
                    return
                original_text = last_user["content"]
        language = detect_language(original_text, payload.language)
        # Preserve raw Sinhala/Singlish spelling and code-switching for GPT.
        model_text = original_text
        with connect_db() as db:
            history_limit = min(100, max(20, CLOUD_CONTEXT_MAX_TURNS * 2 + 1))
            history = db.execute("SELECT role,content FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT ?",
            (conversation_id, history_limit)).fetchall()
        history = list(reversed(history))
        prompt_history = []
        for item in history:
            content = item["content"]
            prompt_history.append({"role": item["role"], "content": content})
        if payload.regenerate and prompt_history and prompt_history[-1]["role"] == "assistant":
            prompt_history.pop()
        messages = [{"role": "system", "content": build_system_prompt(language, payload.response_length)}]
        if len(original_text) > CLOUD_MAX_INPUT_CHARS:
            yield emit("error", {"message": f"GPT input is limited to {CLOUD_MAX_INPUT_CHARS} characters."})
            return
        if payload.share_conversation_context:
            prior_history = prompt_history[:-1] if prompt_history and prompt_history[-1]["role"] == "user" else prompt_history
            context = bound_cloud_history(prior_history, max_turns=CLOUD_CONTEXT_MAX_TURNS,
                token_budget=CLOUD_CONTEXT_TOKEN_BUDGET)
            messages.extend(context)
        messages.append({"role": "user", "content": model_text})
        budget_reservation_id, reservation_state = reserve_cloud_request(owner_id, messages,
            ip_address=getattr(request.state, "client_ip", None))
        if not budget_reservation_id:
            security_event("cloud_request_denied", account_id=owner_id, ip=getattr(request.state, "client_ip", None))
            messages_for = {
                "concurrency": "GPT concurrency limit reached. Try again shortly.",
                "global_requests": "Daily global GPT request limit reached.",
                "identity_requests": "Your daily GPT request limit has been reached.",
                "ip_requests": "Daily request limit for this network address reached.",
                "global_budget": "Daily global GPT spending limit reached.",
                "identity_budget": "Your daily GPT spending limit has been reached.",
                "ip_budget": "Daily GPT reservation limit for this network address reached.",
                "ip_unavailable": "Request could not be safely rate limited; no provider request was made.",
                "budget_store_unavailable": "GPT requests are paused because the spending ledger is unavailable. No provider request was made."
            }
            yield emit("error", {"message": messages_for.get(reservation_state, "GPT budget could not be reserved; request refused.")})
            return
        active_request_id = reservation_state

        storage_error = False
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            owned = db.execute(f"SELECT 1 FROM conversations WHERE id=? AND {ownership_column}=?", (conversation_id, owner_id)).fetchone()
            if not new_conversation and not owned:
                storage_error = True
            if ownership_column == "owner_id" and not payload.regenerate:
                client_ip = getattr(request.state, "client_ip", "unknown")
                if new_conversation:
                    storage_error = storage_error or not take_anonymous_rate_pair(db, category="anonymous_conversation", client_ip=client_ip,
                        ip_limit=ANON_CONVERSATIONS_IP_PER_DAY, global_limit=ANON_CONVERSATIONS_GLOBAL_PER_DAY)
                storage_error = storage_error or not check_anonymous_storage_quota(db, owner_id,
                    conversations=1 if new_conversation else 0, messages=1, text_chars=len(original_text))
                storage_error = storage_error or not take_anonymous_rate_pair(db, category="anonymous_message_write", client_ip=client_ip,
                    ip_limit=ANON_MESSAGES_IP_PER_DAY, global_limit=ANON_MESSAGES_GLOBAL_PER_DAY)
            if not storage_error:
                if new_conversation:
                    stamp = now()
                    retention_class = "account" if ownership_column == "account_id" else "anonymous"
                    db.execute(f"INSERT INTO conversations(id,title,model,{ownership_column},created_at,updated_at,retention_class,last_activity_at) VALUES(?,?,?,?,?,?,?,?)",
                        (conversation_id, original_text[:56] or "New conversation", model, owner_id, stamp, stamp, retention_class, stamp))
                if payload.regenerate:
                    if regenerate_assistant_id is not None:
                        db.execute("DELETE FROM messages WHERE id=? AND conversation_id=?", (regenerate_assistant_id, conversation_id))
                else:
                    db.execute("INSERT INTO messages(conversation_id,role,content,created_at) VALUES(?,?,?,?)",
                        (conversation_id, "user", original_text, now()))
                stamp = now()
                db.execute(f"UPDATE conversations SET model=?,updated_at=?,last_activity_at=? WHERE id=? AND {ownership_column}=?",
                    (model, stamp, stamp, conversation_id, owner_id))
                retention_lease_id = str(uuid.uuid4())
                db.execute("INSERT OR REPLACE INTO conversation_activity_leases(conversation_id,principal_type,principal_id,lease_until,created_at) VALUES(?,?,?,?,?)",
                    (conversation_id, "account" if ownership_column == "account_id" else "anonymous", owner_id,
                     (datetime.now(timezone.utc) + timedelta(seconds=CLOUD_TIMEOUT_SECONDS + 300)).isoformat(), stamp))
        if storage_error:
            cancel_cloud_reservation_before_dispatch(budget_reservation_id)
            budget_reservation_id = None
            yield emit("error", {"message": "Conversation or anonymous storage limit prevented this request; nothing was saved."})
            return
        if payload.remember_preferences:
            save_preferences(owner_id, payload.language, payload.response_length, ownership_column=ownership_column)

        yield emit("meta", {"conversation_id": conversation_id, "model": model, "provider": payload.provider, "language": language})
        answer = ""
        try:
            stream = selected_provider.stream_chat(model, messages, response_length=payload.response_length).__aiter__()
            loop, deadline = asyncio.get_running_loop(), asyncio.get_running_loop().time() + CLOUD_TIMEOUT_SECONDS
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                try:
                    chunk = await asyncio.wait_for(stream.__anext__(), timeout=remaining)
                except StopAsyncIteration:
                    break
                if await request.is_disconnected():
                    return
                answer += chunk
                yield emit("token", {"text": chunk})
            if (cloud_provider.last_terminal_event != "response.completed"
                    or cloud_provider.last_response_status != "completed"):
                yield emit("error", {"message": "GPT response did not complete successfully; it was not saved. No retry was made."})
                return
            if cloud_provider.last_usage is None:
                yield emit("error", {"message": "GPT response completed without usage metadata; it was not marked successful. No retry was made."})
                return
            try:
                reconcile_cloud_reservation(budget_reservation_id, cloud_provider.last_usage)
            except Exception:
                security_event("cloud_settlement_failed", account_id=owner_id,
                    ip=getattr(request.state, "client_ip", None))
                yield emit("error", {"message": "GPT usage could not be recorded safely. The full reservation remains held; no retry was made."})
                return
            budget_reservation_id = None
            if answer:
                with connect_db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    stamp = now()
                    updated = db.execute(f"UPDATE conversations SET updated_at=?,last_activity_at=? WHERE id=? AND {ownership_column}=?", (stamp, stamp, conversation_id, owner_id)).rowcount
                    if not updated:
                        yield emit("error", {"message": "Conversation no longer exists; response was not saved."})
                        return
                    if ownership_column == "owner_id" and not check_anonymous_storage_quota(db, owner_id,
                            messages=1, text_chars=len(answer)):
                        yield emit("error", {"message": "Response received, but anonymous conversation storage is full; it was not saved."})
                        return
                    db.execute("INSERT INTO messages(conversation_id,role,content,created_at) VALUES(?,?,?,?)", (conversation_id, "assistant", answer, now()))
            yield emit("done", {})
        except asyncio.TimeoutError:
            yield emit("error", {"message": "GPT request exceeded its total time limit. No retry was made."})
        except ProviderError as exc:
            yield emit("error", {"message": str(exc)})
    finally:
        # Persistent accounting cleanup is best-effort, but every local gate
        # must be released even when SQLite is locked or unavailable. A failed
        # settlement leaves the reservation untouched (conservative exposure).
        try:
            if budget_reservation_id:
                try:
                    reconcile_cloud_reservation(budget_reservation_id, None)
                except Exception:
                    security_event("cloud_settlement_cleanup_failed", account_id=owner_id,
                        ip=getattr(request.state, "client_ip", None))
        finally:
            if retention_lease_id:
                try:
                    with connect_db() as db:
                        db.execute("DELETE FROM conversation_activity_leases WHERE conversation_id=? AND principal_id=?", (conversation_id, owner_id))
                except Exception:
                    security_event("conversation_activity_lease_cleanup_failed", account_id=owner_id,
                        ip=getattr(request.state, "client_ip", None))
            try:
                try:
                    release_cloud_active_request(active_request_id)
                except Exception:
                    security_event("cloud_active_lease_cleanup_failed", account_id=owner_id,
                        ip=getattr(request.state, "client_ip", None))
            finally:
                try:
                    if queue_registered:
                        async def unregister_waiter():
                            global _waiting_requests
                            async with _queue_lock:
                                _waiting_requests = max(0, _waiting_requests - 1)
                        await asyncio.shield(unregister_waiter())
                finally:
                    if resource_acquired:
                        resource_acquired = False
                        _heavy_resource_gate.release()
                    if acquired:
                        acquired = False
                        _inference_slot.release()


@app.post("/api/chat")
async def chat(request: Request, payload: ChatRequest):
    if payload.conversation_id:
        column, identity = principal(request)
        try:
            get_conversation(payload.conversation_id, identity, ownership_column=column)
        except HTTPException:
            raise HTTPException(404, "Conversation not found") from None
    return StreamingResponse(event_stream(request, payload), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/research/status")
def research_status():
    return research_adapter.status()


@app.get("/api/research/dashboard")
def research_dashboard():
    try:
        return research_adapter.dashboard()
    except ResearchAdapterError as exc:
        raise HTTPException(503, str(exc)) from exc


class ResearchRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    consent: StrictBool


class StrictApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ResearchIntegrity(StrictApiModel):
    disjoint_seed_ranges: bool
    matched_arms: bool
    source_training_is_direct: bool
    agent_inputs_exclude_rule_maps: bool
    no_live_state_path_used: bool


class ResearchMetrics(StrictApiModel):
    heldout_accuracy: float
    heldout_brier: float
    high_conf_negative_transfer_count: int
    calibration_recovery_rate: float
    mean_information_gain: float


class ResearchData(StrictApiModel):
    protocol: Literal["v1.6 preregistered latent environment inference research"]
    integrity: ResearchIntegrity
    decision_metrics: dict[Literal["same_map", "global_permutation", "sparse_change", "independent_map"], ResearchMetrics]
    bootstrap_replicates: int
    map_seeds: list[int]
    evaluation_seeds: list[int]


class ResearchRunResponse(StrictApiModel):
    status: Literal["completed"]
    label: Literal["Experimental simulator observations (separate from chat)"]
    result: ResearchData
    duration_limit_seconds: int
    memory_limit_bytes: int
    state_policy: str


@app.post("/api/research/run", response_model=ResearchRunResponse)
async def research_run(request: Request, payload: ResearchRunRequest):
    global _research_active
    if not research_adapter.status().get("enabled"):
        raise HTTPException(404, "Research execution is disabled.")
    operator_id = getattr(request.state, "account_id", None)
    if not operator_id or operator_id not in RESEARCH_OPERATOR_ACCOUNT_IDS:
        security_event("research_authorization_denied", account_id=operator_id,
            ip=getattr(request.state, "client_ip", None))
        raise HTTPException(403, "Authorized research operator access is required.")
    if not payload.consent:
        raise HTTPException(400, "Confirm the isolated research run to continue.")
    if _inference_slot.locked() or _waiting_requests:
        raise HTTPException(429, "Wait for the local chat model to finish before running research.")
    if _heavy_resource_gate.locked():
        raise HTTPException(429, "Another resource-intensive task is already active.")
    lease = admit_research_run(operator_id)
    if not lease:
        raise HTTPException(429, "Research run quota or concurrency limit reached.")
    acquired = False
    _research_active = True
    try:
        await _heavy_resource_gate.acquire()
        acquired = True
        if _inference_slot.locked() or _waiting_requests:
            raise HTTPException(429, "Wait for the local chat model to finish before running research.")
        worker = asyncio.create_task(asyncio.to_thread(research_adapter.run_sample))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            # Cancelling the HTTP request cannot stop the worker thread/subprocess.
            # Keep the durable lease and local gate until the bounded run actually ends.
            try:
                await asyncio.shield(worker)
            except Exception:
                pass
            raise
    except ResearchAdapterError as exc:
        raise HTTPException(503, str(exc)) from exc
    finally:
        _research_active = False
        if acquired:
            _heavy_resource_gate.release()
        release_durable_operation_lease(lease)


app.mount("/", StaticFiles(directory=ROOT / "static", html=True), name="static")
