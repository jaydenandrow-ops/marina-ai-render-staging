"""Transactional, checksummed SQLite migration runner and read-only planner."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from database_safety import validate_test_database_path
from .versions import MIGRATIONS, Migration

CURRENT_VERSION = MIGRATIONS[-1].version
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class MigrationError(RuntimeError):
    pass


def _open(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    path = validate_test_database_path(path, project_root=PROJECT_ROOT)
    if readonly:
        if not path.is_file():
            raise MigrationError(f"Database does not exist: {path}")
        # URI mode=ro prevents database page/schema writes in dry-run mode.
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    if readonly:
        db.execute("PRAGMA query_only=ON")
    return db


def _applied(db: sqlite3.Connection) -> list[sqlite3.Row]:
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone()
    if not exists:
        return []
    return db.execute("SELECT version,name,checksum,applied_at FROM schema_migrations ORDER BY version").fetchall()


def _validate_history(applied: list[sqlite3.Row], migrations: Iterable[Migration]) -> int:
    definitions = {migration.version: migration for migration in migrations}
    versions = [int(row["version"]) for row in applied]
    if versions != list(range(1, len(versions) + 1)):
        raise MigrationError("Migration history is not contiguous; refusing to change the database.")
    for row in applied:
        migration = definitions.get(int(row["version"]))
        if migration is None:
            raise MigrationError(f"Database revision {row['version']} is newer than this application.")
        if row["name"] != migration.name or row["checksum"] != migration.checksum:
            raise MigrationError(f"Migration checksum/name mismatch at revision {row['version']}; refusing to continue.")
    return versions[-1] if versions else 0


def migrate(path: str | Path, *, migrations: Iterable[Migration] = MIGRATIONS) -> int:
    """Apply pending migrations one at a time; each revision is atomic.

    This function intentionally has no automatic downgrade. Restore a verified
    pre-migration SQLite online backup if recovery is required.
    """
    definitions = tuple(migrations)
    db = _open(Path(path))
    try:
        # Establish the runner table transactionally; no executescript() because
        # sqlite3.executescript commits implicitly.
        db.execute("BEGIN IMMEDIATE")
        db.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL)""")
        db.commit()
        applied = _applied(db)
        current = _validate_history(applied, definitions)
        for migration in definitions:
            if migration.version <= current:
                continue
            if migration.version != current + 1:
                raise MigrationError("Migration definitions are not contiguous; refusing to continue.")
            try:
                db.execute("BEGIN IMMEDIATE")
                migration.upgrade(db)
                db.execute("INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)",
                    (migration.version, migration.name, migration.checksum, datetime.now(timezone.utc).isoformat()))
                violations = db.execute("PRAGMA foreign_key_check").fetchall()
                if violations:
                    raise MigrationError(f"Foreign-key check failed during migration {migration.version}.")
                db.commit()
                current = migration.version
            except Exception as exc:
                db.rollback()
                if isinstance(exc, MigrationError):
                    raise
                raise MigrationError(f"Migration {migration.version} ({migration.name}) rolled back: {type(exc).__name__}") from exc
        return current
    finally:
        db.close()


def _table_counts(db: sqlite3.Connection) -> dict[str, int]:
    result: dict[str, int] = {}
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in ("conversations", "messages", "preferences", "approved_memories", "accounts",
                  "external_identities", "account_emails", "auth_sessions", "email_action_tokens",
                  "email_auth_throttles", "security_rate_limits", "security_operation_leases",
                  "anonymous_storage_usage", "anonymous_storage_global", "anonymous_message_usage_map",
                  "legacy_data_quarantine", "conversation_activity_leases", "data_deletion_tombstones",
                  "account_deletion_requests"):
        if table in tables:
            result[table] = int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
    return result


def _legacy_quarantine_preview(db: sqlite3.Connection) -> dict[str, int]:
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    preview: dict[str, int] = {}
    for table, kind in (("conversations", "conversation"), ("preferences", "preference"),
                        ("approved_memories", "memory")):
        if table not in tables:
            preview[kind] = 0
            continue
        columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
        if "account_id" not in columns:
            preview[kind] = int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
        else:
            preview[kind] = int(db.execute(f'SELECT COUNT(*) FROM "{table}" WHERE account_id IS NULL').fetchone()[0])
    return preview


def dry_run(path: str | Path, *, migrations: Iterable[Migration] = MIGRATIONS) -> dict:
    """Inspect schema and pending revisions without creating or changing anything."""
    definitions = tuple(migrations)
    db = _open(Path(path), readonly=True)
    try:
        applied = _applied(db)
        current = _validate_history(applied, definitions)
        counts = _table_counts(db)
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        pending = [migration for migration in definitions if migration.version > current]
        foreign_key_violations = db.execute("PRAGMA foreign_key_check").fetchall()
        return {
            "database_dialect": "sqlite",
            "read_only": True,
            "current_version": current,
            "target_version": definitions[-1].version if definitions else current,
            "pending": [{"version": item.version, "name": item.name} for item in pending],
            "existing_tables": sorted(tables),
            "row_counts": counts,
            "legacy_quarantine_preview": _legacy_quarantine_preview(db),
            "integrity_check": db.execute("PRAGMA integrity_check").fetchone()[0],
            "foreign_key_violations": len(foreign_key_violations),
            "ownership_note": "Dry-run does not assign account ownership or modify rows.",
        }
    finally:
        db.close()


def print_dry_run(path: str | Path, *, migrations: Iterable[Migration] = MIGRATIONS) -> None:
    print(json.dumps(dry_run(path, migrations=migrations), indent=2, sort_keys=True))

