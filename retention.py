"""Fail-closed, explicitly invoked conversation retention operations.

No application startup hook calls cleanup. Current execution is deliberately
limited to test-mode SQLite files beneath MARINA_TEST_ISOLATION_ROOT.
"""
from __future__ import annotations

import os
import hashlib
import argparse
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from database_safety import validate_test_database_path

POLICY_VERSION = "retention-v1"
ANONYMOUS_DAYS = 30
MAX_BATCH = 500
PROJECT_ROOT = Path(__file__).resolve().parent


class RetentionSafetyError(RuntimeError):
    pass


def _validated(path: str | Path) -> Path:
    if os.getenv("GENESIS_ENV") != "test":
        raise RetentionSafetyError("Retention operations are restricted to isolated test databases.")
    root = os.getenv("MARINA_TEST_ISOLATION_ROOT", "").strip()
    if not root:
        raise RetentionSafetyError("A verified test isolation root is required.")
    try:
        target = validate_test_database_path(path, environment="test", isolation_root=root,
            project_root=PROJECT_ROOT)
    except (RuntimeError, OSError, ValueError):
        raise RetentionSafetyError("Database path is outside the verified test isolation root.") from None
    if not target.is_file():
        raise RetentionSafetyError("Retention database must already exist.")
    return target


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _connect(path: Path, *, readonly: bool) -> sqlite3.Connection:
    if readonly:
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)
        db.execute("PRAGMA query_only=ON")
    else:
        db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def _require_schema(db: sqlite3.Connection) -> None:
    try:
        row = db.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        if row is None or row[0] != 8:
            raise RetentionSafetyError("Retention schema revision 8 is required.")
    except sqlite3.Error:
        raise RetentionSafetyError("Retention schema is unavailable; refusing operation.") from None


def _eligible_rows(db: sqlite3.Connection, cutoff: datetime, *, active_at: datetime | None = None,
                   limit: int | None = None) -> tuple[list[sqlite3.Row], dict[str, int]]:
    lease_check = (active_at or cutoff).isoformat()
    query = """SELECT c.id,c.owner_id,c.account_id,c.retention_class,c.last_activity_at,
        EXISTS(SELECT 1 FROM legacy_data_quarantine q WHERE q.object_type='conversation' AND q.object_id=c.id) AS quarantined,
        EXISTS(SELECT 1 FROM conversation_activity_leases l WHERE l.conversation_id=c.id AND l.lease_until>?) AS active_lease,
        EXISTS(SELECT 1 FROM data_deletion_tombstones t WHERE t.object_type='conversation' AND t.object_id=c.id) AS tombstoned
        FROM conversations c"""
    params: tuple = (lease_check,)
    if limit is not None:
        # All new activity timestamps use canonical UTC ISO form. SQL narrows a
        # single bounded candidate page; Python still parses every timestamp and
        # fails closed on malformed or timezone-naive values.
        query += """ WHERE c.retention_class='anonymous' AND c.owner_id IS NOT NULL
            AND c.account_id IS NULL AND c.last_activity_at IS NOT NULL
            AND c.last_activity_at<=?
            AND NOT EXISTS(SELECT 1 FROM legacy_data_quarantine q WHERE q.object_type='conversation' AND q.object_id=c.id)
            AND NOT EXISTS(SELECT 1 FROM conversation_activity_leases l WHERE l.conversation_id=c.id AND l.lease_until>?)
            AND NOT EXISTS(SELECT 1 FROM data_deletion_tombstones t WHERE t.object_type='conversation' AND t.object_id=c.id)"""
        query += " ORDER BY c.last_activity_at,c.id LIMIT ?"
        params = (lease_check, cutoff.isoformat(), lease_check, limit)
    else:
        params = (lease_check,)
        query += " ORDER BY c.last_activity_at,c.id"
    rows = db.execute(query, params).fetchall()
    eligible: list[sqlite3.Row] = []
    excluded = {"legacy_unknown": 0, "invalid_metadata": 0, "quarantined": 0, "active": 0,
                "account_owned": 0, "not_expired": 0, "already_deleted": 0}
    for row in rows:
        if row["account_id"] is not None or row["retention_class"] == "account":
            excluded["account_owned"] += 1
        elif row["retention_class"] == "legacy_unknown":
            excluded["legacy_unknown"] += 1
        elif row["retention_class"] != "anonymous" or not row["owner_id"] or not _parse_utc(row["last_activity_at"]):
            excluded["invalid_metadata"] += 1
        elif row["quarantined"]:
            excluded["quarantined"] += 1
        elif row["active_lease"]:
            excluded["active"] += 1
        elif row["tombstoned"]:
            excluded["already_deleted"] += 1
        elif _parse_utc(row["last_activity_at"]) > cutoff:
            excluded["not_expired"] += 1
        else:
            eligible.append(row)
    if limit is not None:
        eligible = eligible[:limit]
    return eligible, excluded


def preview(path: str | Path, *, now: datetime | None = None) -> dict:
    """Read-only candidate preview. Emits counts and cutoff only, no row IDs/content."""
    target = _validated(path)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise RetentionSafetyError("A timezone-aware UTC reference time is required.")
    current = current.astimezone(timezone.utc)
    cutoff = current - timedelta(days=ANONYMOUS_DAYS)
    db = _connect(target, readonly=True)
    try:
        _require_schema(db)
        rows, excluded = _eligible_rows(db, cutoff, active_at=current)
        return {"read_only": True, "policy_version": POLICY_VERSION,
            "cutoff_utc": cutoff.isoformat(), "eligible_count": len(rows),
            "excluded_counts": excluded}
    finally:
        db.close()


def cleanup_batch(path: str | Path, *, now: datetime | None = None, limit: int = MAX_BATCH) -> dict:
    """Idempotently delete a bounded batch; disabled unless an isolated test opts in."""
    if os.getenv("RETENTION_CLEANUP_ENABLED") != "1":
        raise RetentionSafetyError("Retention cleanup is disabled.")
    if isinstance(limit, bool) or not 1 <= limit <= MAX_BATCH:
        raise RetentionSafetyError("Cleanup batch limit must be between 1 and 500.")
    target = _validated(path)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise RetentionSafetyError("A timezone-aware UTC reference time is required.")
    current = current.astimezone(timezone.utc)
    cutoff = current - timedelta(days=ANONYMOUS_DAYS)
    db = _connect(target, readonly=False)
    try:
        db.execute("BEGIN IMMEDIATE")
        _require_schema(db)
        rows, _ = _eligible_rows(db, cutoff, active_at=current, limit=limit)
        deleted_count = 0
        for row in rows:
            # Recheck all ownership, lease, quarantine and timestamp conditions
            # under the same write lock immediately before cascading deletion.
            current_row = db.execute("""SELECT retention_class,owner_id,account_id,last_activity_at,
                EXISTS(SELECT 1 FROM conversation_activity_leases WHERE conversation_id=? AND lease_until>?) AS active,
                EXISTS(SELECT 1 FROM legacy_data_quarantine WHERE object_type='conversation' AND object_id=conversations.id) AS quarantined
                FROM conversations WHERE id=?""", (row["id"], current.isoformat(), row["id"])).fetchone()
            if (not current_row or current_row["retention_class"] != "anonymous" or not current_row["owner_id"]
                    or current_row["account_id"] is not None or current_row["active"] or current_row["quarantined"]
                    or not _parse_utc(current_row["last_activity_at"])
                    or _parse_utc(current_row["last_activity_at"]) > cutoff):
                continue
            db.execute("INSERT OR IGNORE INTO data_deletion_tombstones(object_type,object_id,deleted_at,policy_version) VALUES('conversation',?,?,?)",
                (row["id"], current.isoformat(), POLICY_VERSION))
            deleted = db.execute("DELETE FROM conversations WHERE id=? AND owner_id=? AND account_id IS NULL AND retention_class='anonymous'",
                (row["id"], row["owner_id"]))
            deleted_count += deleted.rowcount
        db.commit()
        return {"deleted_count": deleted_count, "policy_version": POLICY_VERSION,
            "cutoff_utc": cutoff.isoformat(), "batch_limit": limit}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


async def delete_account(path: str | Path, account_id: str, *, image_cleanup, now: datetime | None = None) -> dict:
    """Two-phase account purge for an explicitly authorized account deletion.

    The account is locked and sessions revoked before external image storage is
    purged. Any failure leaves a content-free, retry/audit marker and the account
    locked; account-owned DB rows are removed only after image cleanup succeeds.
    This function is isolated to synthetic test databases until separate release
    approval and production operational controls exist.
    """
    target = _validated(path)
    if not account_id or len(account_id) > 128:
        raise RetentionSafetyError("A valid account identity is required.")
    stamp_dt = now or datetime.now(timezone.utc)
    if stamp_dt.tzinfo is None or stamp_dt.utcoffset() is None:
        raise RetentionSafetyError("A timezone-aware UTC timestamp is required.")
    stamp = stamp_dt.astimezone(timezone.utc).isoformat()
    request_key = hashlib.sha256(account_id.encode("utf-8")).hexdigest()
    db = _connect(target, readonly=False)
    try:
        db.execute("BEGIN IMMEDIATE")
        _require_schema(db)
        account = db.execute("SELECT status FROM accounts WHERE id=?", (account_id,)).fetchone()
        if account is None:
            db.rollback()
            return {"deleted": False, "status": "not_found"}
        active = db.execute("SELECT 1 FROM conversation_activity_leases WHERE principal_type='account' AND principal_id=? AND lease_until>? LIMIT 1",
            (account_id, stamp)).fetchone()
        if active:
            db.rollback()
            return {"deleted": False, "status": "active_conversation"}
        db.execute("UPDATE accounts SET status='locked',updated_at=? WHERE id=?", (stamp, account_id))
        db.execute("UPDATE auth_sessions SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL", (stamp, account_id))
        db.execute("UPDATE email_action_tokens SET consumed_at=? WHERE account_id=? AND consumed_at IS NULL", (stamp, account_id))
        db.execute("INSERT INTO account_deletion_requests(account_id,requested_at,status,updated_at,failure_code) VALUES(?,?,'pending',?,NULL) ON CONFLICT(account_id) DO UPDATE SET status='pending',updated_at=excluded.updated_at,failure_code=NULL",
            (request_key, stamp, stamp))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


    try:
        result = image_cleanup(account_id)
        if hasattr(result, "__await__"):
            await result
    except Exception:
        db = _connect(target, readonly=False)
        try:
            db.execute("UPDATE account_deletion_requests SET status='failed',updated_at=?,failure_code='image_cleanup_failed' WHERE account_id=?",
                (stamp, request_key))
        finally:
            db.close()
        return {"deleted": False, "status": "pending_image_cleanup"}

    db = _connect(target, readonly=False)
    try:
        db.execute("BEGIN IMMEDIATE")
        _require_schema(db)
        active = db.execute("SELECT 1 FROM conversation_activity_leases WHERE principal_type='account' AND principal_id=? AND lease_until>? LIMIT 1",
            (account_id, stamp)).fetchone()
        if active:
            db.rollback()
            return {"deleted": False, "status": "active_conversation"}
        for row in db.execute("SELECT id FROM conversations WHERE account_id=?", (account_id,)).fetchall():
            db.execute("INSERT OR IGNORE INTO data_deletion_tombstones(object_type,object_id,deleted_at,policy_version) VALUES('conversation',?,?,?)",
                (row[0], stamp, POLICY_VERSION))
        db.execute("DELETE FROM conversations WHERE account_id=?", (account_id,))
        db.execute("DELETE FROM preferences WHERE account_id=?", (account_id,))
        db.execute("DELETE FROM approved_memories WHERE account_id=?", (account_id,))
        db.execute("DELETE FROM cloud_active_requests WHERE owner_id=?", (account_id,))
        # Preserve financial reservations/usage totals while replacing the
        # durable account identifier with a one-way tombstone pseudonym.
        deleted_scope = "deleted-" + request_key
        db.execute("UPDATE cloud_budget_daily SET scope_id=? WHERE scope_id=?", (deleted_scope, account_id))
        db.execute("UPDATE cloud_budget_reservations SET owner_id=? WHERE owner_id=?", (deleted_scope, account_id))
        db.execute("DELETE FROM external_identities WHERE account_id=?", (account_id,))
        db.execute("DELETE FROM account_emails WHERE account_id=?", (account_id,))
        db.execute("DELETE FROM email_action_tokens WHERE account_id=?", (account_id,))
        db.execute("DELETE FROM auth_sessions WHERE account_id=?", (account_id,))
        db.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        db.execute("INSERT OR REPLACE INTO data_deletion_tombstones(object_type,object_id,deleted_at,policy_version) VALUES('account',?,?,?)",
            (request_key, stamp, POLICY_VERSION))
        db.execute("UPDATE account_deletion_requests SET status='complete',updated_at=?,failure_code=NULL WHERE account_id=?",
            (stamp, request_key))
        db.commit()
        return {"deleted": True, "status": "complete"}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Isolated MARINA AI retention preview/cleanup.")
    parser.add_argument("--db-path", required=True, help="Explicit disposable SQLite database path.")
    parser.add_argument("--apply", action="store_true", help="Apply one bounded test-only cleanup batch.")
    parser.add_argument("--limit", type=int, default=MAX_BATCH)
    parser.add_argument("--confirm", default="", help="Must equal RETENTION-CLEANUP-TEST-ONLY to apply.")
    args = parser.parse_args()
    if not args.apply:
        print(json.dumps(preview(args.db_path), sort_keys=True))
        return 0
    if args.confirm != "RETENTION-CLEANUP-TEST-ONLY":
        parser.error("--apply requires --confirm RETENTION-CLEANUP-TEST-ONLY")
    print(json.dumps(cleanup_batch(args.db_path, limit=args.limit), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
