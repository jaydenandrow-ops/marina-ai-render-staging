"""Explicit SQLite/PostgreSQL connection support.

SQLite remains the default backend. PostgreSQL is opt-in through
GENESIS_DATABASE_URL and requires psycopg 3 + psycopg_pool. This module never
loads dotenv and never opens a database at import time.
"""
from __future__ import annotations

import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator
from urllib.parse import parse_qs, unquote, urlsplit

POSTGRES_URL_PREFIXES = ("postgres://", "postgresql://", "postgresql+psycopg://")
_IMMEDIATE_LOCK_KEY = 5_377_749_112_829_171_023
_POOL_LOCK = threading.Lock()


def database_url() -> str:
    return os.getenv("GENESIS_DATABASE_URL", "").strip()


def is_postgres_url(value: str | None = None) -> bool:
    candidate = database_url() if value is None else value.strip()
    return candidate.startswith(POSTGRES_URL_PREFIXES)


def postgres_connect_info(value: str) -> str:
    """Normalize common PostgreSQL URL schemes for psycopg."""
    if value.startswith("postgresql+psycopg://"):
        return "postgresql://" + value[len("postgresql+psycopg://"):]
    if value.startswith("postgres://"):
        return "postgresql://" + value[len("postgres://"):]
    if value.startswith("postgresql://"):
        return value
    raise ValueError("PostgreSQL URL scheme is not supported.")


def validate_test_postgres_url(value: str) -> None:
    """Reject non-local, default-port, or non-test database targets in test mode."""
    try:
        parsed = urlsplit(postgres_connect_info(value))
        database_name = unquote(parsed.path.lstrip("/"))
        port = parsed.port or 5432
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Test PostgreSQL URL is invalid.") from exc
    if parsed.hostname not in {"127.0.0.1", "::1", "localhost"} or port == 5432:
        raise RuntimeError("Test PostgreSQL must use loopback on a dedicated non-5432 port.")
    # Keep the general prefix rule while allowing this operator-provisioned,
    # explicitly named disposable integration database.
    if not database_name.startswith("marina_test_") and database_name != "marina_integration_test":
        raise RuntimeError("Test PostgreSQL database name is not on the isolated test allowlist.")


def validate_production_postgres_url(value: str) -> None:
    try:
        parsed = urlsplit(postgres_connect_info(value))
        sslmode = parse_qs(parsed.query).get("sslmode", [""])[0].lower()
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Production PostgreSQL URL is invalid.") from exc
    if not parsed.hostname or not parsed.path.strip("/"):
        raise RuntimeError("Production PostgreSQL URL must include a host and database name.")
    if sslmode != "verify-full":
        raise RuntimeError("Production PostgreSQL URL must require sslmode=verify-full.")


def qmark_to_pyformat(sql: str) -> str:
    """Convert DB-API qmark placeholders outside quoted SQL strings."""
    output: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(sql):
        char = sql[i]
        if quote:
            output.append(char)
            if char == quote:
                if i + 1 < len(sql) and sql[i + 1] == quote:
                    output.append(sql[i + 1])
                    i += 1
                else:
                    quote = None
        elif char in ("'", '"'):
            quote = char
            output.append(char)
        elif char == "?":
            output.append("%s")
        else:
            output.append(char)
        i += 1
    return "".join(output)


class HybridRow:
    """Small sqlite3.Row-compatible mapping/sequence for psycopg rows."""
    __slots__ = ("_names", "_values", "_map")

    def __init__(self, names: tuple[str, ...], values: tuple[object, ...]):
        self._names = names
        self._values = values
        self._map = dict(zip(names, values))

    def __getitem__(self, key):
        if isinstance(key, str):
            return self._map[key]
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def keys(self):
        return self._names


def _psycopg_row_factory(cursor):
    # Psycopg may invoke the row factory for commands without result columns
    # (for example BEGIN, INSERT, COMMIT, or ROLLBACK). Such cursors have no
    # description; no row maker is needed, but the factory must remain callable.
    description = cursor.description
    names = tuple(column.name for column in description) if description is not None else ()
    return lambda values: HybridRow(names, values)


def _rewrite_postgres_sql(sql: str) -> str:
    sql = qmark_to_pyformat(sql)
    # SQLite scalar MAX(a,b) is PostgreSQL GREATEST(a,b). These occur only in
    # application arithmetic expressions, never as aggregate MAX queries.
    sql = re.sub(r"\bMAX\s*\(\s*0\s*,", "GREATEST(0,", sql, flags=re.IGNORECASE)
    return sql


class PostgresConnection:
    """Narrow adapter for current DB-API call sites; not a SQL dialect engine."""
    def __init__(self, raw, integrity_error, error, release=None):
        self._raw = raw
        self._integrity_error = integrity_error
        self._error = error
        self._release = release

    @property
    def row_factory(self):
        return None

    @row_factory.setter
    def row_factory(self, value):
        # Application code may assign sqlite3.Row; the connection is already
        # configured with HybridRow by the pool's row_factory callback.
        return None

    def execute(self, sql: str, parameters=()):
        if sql.strip().upper() == "BEGIN IMMEDIATE":
            try:
                status = self._raw.info.transaction_status
                idle = status == 0  # psycopg.pq.TransactionStatus.IDLE
                if idle:
                    self._raw.execute("BEGIN")
                # Cross-worker serialization preserves SQLite's write-admission
                # semantics for protected quota/budget/token transactions.
                return self._raw.execute("SELECT pg_advisory_xact_lock(%s)", (_IMMEDIATE_LOCK_KEY,))
            except self._integrity_error:
                raise
            except self._error as exc:
                raise sqlite3.OperationalError("PostgreSQL transaction could not be started safely.") from exc
        try:
            return self._raw.execute(_rewrite_postgres_sql(sql), parameters)
        except self._integrity_error as exc:
            raise sqlite3.IntegrityError("PostgreSQL constraint rejected the operation.") from exc
        except self._error as exc:
            raise sqlite3.OperationalError("PostgreSQL operation failed.") from exc

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        if self._release:
            release, self._release = self._release, None
            release(self._raw)


def _get_pool():
    url = database_url()
    if not is_postgres_url(url):
        raise RuntimeError("GENESIS_DATABASE_URL must use a PostgreSQL URL scheme.")
    try:
        from psycopg import Error, IntegrityError
        from psycopg_pool import ConnectionPool
    except ImportError as exc:
        raise RuntimeError("PostgreSQL backend requires the declared psycopg and psycopg-pool dependencies.") from exc

    # Lazy, per-process pool. TLS is mandatory for remote production hosts;
    # local loopback test servers may explicitly use sslmode=disable.
    pool = getattr(_pool, "_instance", None)
    if pool is None:
        try:
            min_size = int(os.getenv("GENESIS_DB_POOL_MIN", "1"))
            max_size = int(os.getenv("GENESIS_DB_POOL_MAX", "8"))
        except ValueError as exc:
            raise RuntimeError("PostgreSQL pool size configuration is invalid.") from exc
        if not (1 <= min_size <= max_size <= 32):
            raise RuntimeError("PostgreSQL pool sizes must satisfy 1 <= min <= max <= 32.")

        def configure(conn):
            conn.row_factory = _psycopg_row_factory

        pool = ConnectionPool(conninfo=postgres_connect_info(url), min_size=min_size,
            max_size=max_size, timeout=10, open=False, kwargs={"connect_timeout": 10,
            "application_name": "marina-ai"}, configure=configure)
        try:
            pool.open(wait=True)
        except Exception:
            pool.close()
            raise RuntimeError("PostgreSQL connection pool is unavailable.") from None
        _pool._instance = (pool, IntegrityError, Error)
    else:
        pool, IntegrityError, Error = pool
    return pool, IntegrityError, Error


def _pool():
    with _POOL_LOCK:
        return _get_pool()


@contextmanager
def postgres_connection() -> Iterator[PostgresConnection]:
    adapter = checkout_postgres()
    raw = adapter._raw
    try:
        yield adapter
        raw.commit()
    except Exception:
        raw.rollback()
        raise
    finally:
        adapter.close()


def checkout_postgres() -> PostgresConnection:
    pool, integrity_error, error = _pool()
    try:
        raw = pool.getconn(timeout=10)
    except Exception:
        raise sqlite3.OperationalError("PostgreSQL connection is unavailable.") from None
    return PostgresConnection(raw, integrity_error, error, release=pool.putconn)


def close_postgres_pool() -> None:
    with _POOL_LOCK:
        instance = getattr(_pool, "_instance", None)
        if instance:
            pool, _, _ = instance
            pool.close()
            _pool._instance = None
