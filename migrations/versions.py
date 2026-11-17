"""Append-only, transactional SQLite schema revisions.

Do not edit an applied revision. Add a new revision with a new immutable checksum.
All DDL here is intentionally expressed as individual statements because
sqlite3.executescript() implicitly commits and breaks transactional migration.
"""

from __future__ import annotations

import hashlib
import inspect
import sqlite3
from dataclasses import dataclass
from typing import Callable


Upgrade = Callable[[sqlite3.Connection], None]


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    checksum: str
    upgrade: Upgrade


def _checksum(upgrade: Upgrade) -> str:
    # Hash the immutable migration implementation so accidental edits to an
    # applied revision fail closed when a database is opened by a newer build.
    return hashlib.sha256(inspect.getsource(upgrade).encode("utf-8")).hexdigest()


def _v1_core_schema(db: sqlite3.Connection) -> None:
    # This baseline is safe for both an empty database and an existing Phase 1
    # database because CREATE IF NOT EXISTS never replaces existing user tables.
    db.execute("""CREATE TABLE IF NOT EXISTS conversations (
        id TEXT PRIMARY KEY, title TEXT NOT NULL, model TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK(role IN ('user','assistant')),
        content TEXT NOT NULL, created_at TEXT NOT NULL)""")
    db.execute("CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id,id)")
    db.execute("""CREATE TABLE IF NOT EXISTS preferences (
        id INTEGER PRIMARY KEY CHECK(id=1), language TEXT NOT NULL,
        response_length TEXT NOT NULL, consented_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS approved_memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL,
        created_at TEXT NOT NULL)""")


def _columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def _v2_phase1_ownership_and_anonymous_sessions(db: sqlite3.Connection) -> None:
    # owner_id preserves Phase 1's already-issued anonymous ownership. NULL legacy
    # rows remain inaccessible. No ownership is inferred or assigned here.
    for table in ("conversations", "preferences", "approved_memories"):
        if "owner_id" not in _columns(db, table):
            db.execute(f"ALTER TABLE {table} ADD COLUMN owner_id TEXT")
    db.execute("CREATE INDEX IF NOT EXISTS conversations_owner_updated_idx ON conversations(owner_id,updated_at DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS memories_owner_idx ON approved_memories(owner_id,id DESC)")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS preferences_owner_unique_idx ON preferences(owner_id)")
    db.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
        token_hash TEXT PRIMARY KEY, owner_id TEXT NOT NULL,
        expires_at TEXT NOT NULL, created_at TEXT NOT NULL)""")


def _v3_durable_account_schema(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL CHECK(status IN ('pending','active','locked','deleted')),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS external_identities (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        provider TEXT NOT NULL, subject TEXT NOT NULL,
        email_snapshot TEXT, email_verified_at TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(provider,subject))""")
    db.execute("CREATE INDEX IF NOT EXISTS external_identities_account_idx ON external_identities(account_id)")
    db.execute("""CREATE TABLE IF NOT EXISTS account_emails (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        email_normalized TEXT NOT NULL,
        verified_at TEXT,
        is_primary INTEGER NOT NULL DEFAULT 0 CHECK(is_primary IN (0,1)),
        created_at TEXT NOT NULL)""")
    db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS account_emails_verified_unique_idx
        ON account_emails(email_normalized) WHERE verified_at IS NOT NULL""")
    db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS account_emails_primary_unique_idx
        ON account_emails(account_id) WHERE is_primary=1 AND verified_at IS NOT NULL""")
    db.execute("CREATE INDEX IF NOT EXISTS account_emails_account_idx ON account_emails(account_id)")
    db.execute("""CREATE TABLE IF NOT EXISTS auth_sessions (
        token_hash TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        csrf_token_hash TEXT NOT NULL,
        auth_method TEXT NOT NULL CHECK(auth_method IN ('google','email')),
        created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
        idle_expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL,
        revoked_at TEXT, device_label TEXT)""")
    db.execute("CREATE INDEX IF NOT EXISTS auth_sessions_account_idx ON auth_sessions(account_id,revoked_at)")
    db.execute("CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(idle_expires_at,absolute_expires_at)")
    db.execute("""CREATE TABLE IF NOT EXISTS email_action_tokens (
        token_hash TEXT PRIMARY KEY,
        purpose TEXT NOT NULL CHECK(purpose IN ('verify_email','sign_in','recover_account','link_identity')),
        account_id TEXT REFERENCES accounts(id) ON DELETE CASCADE,
        email_normalized TEXT NOT NULL,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        consumed_at TEXT, attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count>=0))""")
    db.execute("CREATE INDEX IF NOT EXISTS email_action_account_idx ON email_action_tokens(account_id,purpose)")
    db.execute("CREATE INDEX IF NOT EXISTS email_action_expiry_idx ON email_action_tokens(expires_at,consumed_at)")

    # Nullable account_id is a transitional ownership field. Existing anonymous
    # owner_id values stay intact for Phase 1; account-scoped APIs must use only
    # account_id and therefore cannot see these rows until an explicit claim.
    for table in ("conversations", "preferences", "approved_memories"):
        if "account_id" not in _columns(db, table):
            db.execute(f"ALTER TABLE {table} ADD COLUMN account_id TEXT REFERENCES accounts(id) ON DELETE RESTRICT")
    db.execute("CREATE INDEX IF NOT EXISTS conversations_account_updated_idx ON conversations(account_id,updated_at DESC)")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS preferences_account_unique_idx ON preferences(account_id)")
    db.execute("CREATE INDEX IF NOT EXISTS memories_account_idx ON approved_memories(account_id,id DESC)")

    # A durable quarantine manifest makes the no-automatic-claim rule explicit.
    # It references original rows by type/id without copying or deleting content.
    db.execute("""CREATE TABLE IF NOT EXISTS legacy_data_quarantine (
        object_type TEXT NOT NULL CHECK(object_type IN ('conversation','preference','memory')),
        object_id TEXT NOT NULL, reason TEXT NOT NULL,
        quarantined_at TEXT NOT NULL,
        PRIMARY KEY(object_type,object_id))""")
    stamp = "strftime('%Y-%m-%dT%H:%M:%fZ','now')"
    db.execute(f"""INSERT OR IGNORE INTO legacy_data_quarantine(object_type,object_id,reason,quarantined_at)
        SELECT 'conversation',CAST(id AS TEXT),'pre-account record; ownership requires explicit claim',{stamp}
        FROM conversations WHERE account_id IS NULL""")
    db.execute(f"""INSERT OR IGNORE INTO legacy_data_quarantine(object_type,object_id,reason,quarantined_at)
        SELECT 'preference',CAST(id AS TEXT),'pre-account record; ownership requires explicit claim',{stamp}
        FROM preferences WHERE account_id IS NULL""")
    db.execute(f"""INSERT OR IGNORE INTO legacy_data_quarantine(object_type,object_id,reason,quarantined_at)
        SELECT 'memory',CAST(id AS TEXT),'pre-account record; ownership requires explicit claim',{stamp}
        FROM approved_memories WHERE account_id IS NULL""")

    # Keep the manifest complete while Phase 1 anonymous sessions remain active.
    # Such rows remain accessible only through Phase 1 owner_id checks; future
    # account-scoped code must use account_id, never this manifest as authority.
    for table, kind, key in (("conversations", "conversation", "id"),
                             ("preferences", "preference", "id"),
                             ("approved_memories", "memory", "id")):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS quarantine_{table}_insert
            AFTER INSERT ON {table} WHEN NEW.account_id IS NULL BEGIN
                INSERT OR IGNORE INTO legacy_data_quarantine(object_type,object_id,reason,quarantined_at)
                VALUES('{kind}',CAST(NEW.{key} AS TEXT),'pre-account record; ownership requires explicit claim',{stamp});
            END""")
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS quarantine_{table}_ownership_update
            AFTER UPDATE OF account_id ON {table} BEGIN
                DELETE FROM legacy_data_quarantine WHERE object_type='{kind}' AND object_id=CAST(NEW.{key} AS TEXT);
                INSERT OR IGNORE INTO legacy_data_quarantine(object_type,object_id,reason,quarantined_at)
                SELECT '{kind}',CAST(NEW.{key} AS TEXT),'pre-account record; ownership requires explicit claim',{stamp}
                WHERE NEW.account_id IS NULL;
            END""")
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS quarantine_{table}_delete
            AFTER DELETE ON {table} BEGIN
                DELETE FROM legacy_data_quarantine WHERE object_type='{kind}' AND object_id=CAST(OLD.{key} AS TEXT);
            END""")


def _v4_google_oidc_transactions(db: sqlite3.Connection) -> None:
    # Temporary OAuth state is one-use and expires quickly. The browser-bound
    # transaction cookie carries the PKCE verifier; only digests are persisted.
    db.execute("""CREATE TABLE IF NOT EXISTS oauth_transactions (
        state_hash TEXT PRIMARY KEY,
        nonce_hash TEXT NOT NULL,
        binding_hash TEXT NOT NULL,
        verifier_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed_at TEXT)""")
    db.execute("CREATE INDEX IF NOT EXISTS oauth_transactions_expiry_idx ON oauth_transactions(expires_at,consumed_at)")


def _v5_email_auth_throttling(db: sqlite3.Connection) -> None:
    # Bucket identifiers are keyed HMACs; raw IP addresses and request emails
    # are never copied into this abuse-control table.
    db.execute("""CREATE TABLE IF NOT EXISTS email_auth_throttles (
        bucket_hash TEXT PRIMARY KEY,
        bucket_kind TEXT NOT NULL CHECK(bucket_kind IN ('ip','email')),
        window_started_at TEXT NOT NULL,
        attempts INTEGER NOT NULL CHECK(attempts>=1),
        cooldown_until TEXT,
        updated_at TEXT NOT NULL)""")
    db.execute("CREATE INDEX IF NOT EXISTS email_auth_throttles_updated_idx ON email_auth_throttles(updated_at)")


def _v6_durable_security_quotas(db: sqlite3.Connection) -> None:
    # Generic, cross-worker rate buckets contain only keyed pseudonymous IDs.
    db.execute("""CREATE TABLE IF NOT EXISTS security_rate_limits (
        bucket_hash TEXT PRIMARY KEY, category TEXT NOT NULL,
        window_started_at TEXT NOT NULL, attempts INTEGER NOT NULL CHECK(attempts>=1),
        updated_at TEXT NOT NULL)""")
    db.execute("CREATE INDEX IF NOT EXISTS security_rate_limits_updated_idx ON security_rate_limits(updated_at)")
    db.execute("""CREATE TABLE IF NOT EXISTS security_operation_leases (
        lease_id TEXT PRIMARY KEY, operation TEXT NOT NULL, principal_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL, created_at TEXT NOT NULL)""")
    db.execute("CREATE INDEX IF NOT EXISTS security_operation_leases_scope_idx ON security_operation_leases(operation,principal_hash,expires_at)")
    db.execute("""CREATE TABLE IF NOT EXISTS anonymous_storage_usage (
        owner_id TEXT PRIMARY KEY, conversation_count INTEGER NOT NULL DEFAULT 0 CHECK(conversation_count>=0),
        message_count INTEGER NOT NULL DEFAULT 0 CHECK(message_count>=0),
        text_chars INTEGER NOT NULL DEFAULT 0 CHECK(text_chars>=0), updated_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS anonymous_storage_global (
        id INTEGER PRIMARY KEY CHECK(id=1), conversation_count INTEGER NOT NULL DEFAULT 0 CHECK(conversation_count>=0),
        message_count INTEGER NOT NULL DEFAULT 0 CHECK(message_count>=0),
        text_chars INTEGER NOT NULL DEFAULT 0 CHECK(text_chars>=0), updated_at TEXT NOT NULL)""")
    db.execute("INSERT OR IGNORE INTO anonymous_storage_global(id,updated_at) VALUES(1,strftime('%Y-%m-%dT%H:%M:%fZ','now'))")
    db.execute("""CREATE TABLE IF NOT EXISTS anonymous_message_usage_map (
        message_id INTEGER PRIMARY KEY, conversation_id TEXT NOT NULL, owner_id TEXT NOT NULL,
        text_chars INTEGER NOT NULL CHECK(text_chars>=0))""")
    # Backfill existing Phase 1 anonymous data without changing ownership/content.
    db.execute("""INSERT OR IGNORE INTO anonymous_storage_usage(owner_id,conversation_count,message_count,text_chars,updated_at)
        SELECT c.owner_id,COUNT(DISTINCT c.id),COUNT(m.id),COALESCE(SUM(length(m.content)),0),
        strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM conversations c
        LEFT JOIN messages m ON m.conversation_id=c.id
        WHERE c.owner_id IS NOT NULL AND c.account_id IS NULL GROUP BY c.owner_id""")
    db.execute("""UPDATE anonymous_storage_global SET
        conversation_count=(SELECT COUNT(*) FROM conversations WHERE owner_id IS NOT NULL AND account_id IS NULL),
        message_count=(SELECT COUNT(*) FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE c.owner_id IS NOT NULL AND c.account_id IS NULL),
        text_chars=COALESCE((SELECT SUM(length(m.content)) FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE c.owner_id IS NOT NULL AND c.account_id IS NULL),0),
        updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=1""")
    db.execute("""INSERT OR IGNORE INTO anonymous_message_usage_map(message_id,conversation_id,owner_id,text_chars)
        SELECT m.id,m.conversation_id,c.owner_id,length(m.content) FROM messages m
        JOIN conversations c ON c.id=m.conversation_id WHERE c.owner_id IS NOT NULL AND c.account_id IS NULL""")
    # Triggers make quotas correct for all application write paths and deletes.
    db.execute("""CREATE TRIGGER IF NOT EXISTS anonymous_conversation_insert AFTER INSERT ON conversations
        WHEN NEW.owner_id IS NOT NULL AND NEW.account_id IS NULL BEGIN
        INSERT INTO anonymous_storage_usage(owner_id,conversation_count,message_count,text_chars,updated_at)
        VALUES(NEW.owner_id,1,0,0,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        ON CONFLICT(owner_id) DO UPDATE SET conversation_count=conversation_count+1,updated_at=excluded.updated_at;
        UPDATE anonymous_storage_global SET conversation_count=conversation_count+1,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=1;
    END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS anonymous_conversation_delete AFTER DELETE ON conversations
        WHEN OLD.owner_id IS NOT NULL AND OLD.account_id IS NULL BEGIN
        UPDATE anonymous_storage_usage SET conversation_count=MAX(0,conversation_count-1),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE owner_id=OLD.owner_id;
        UPDATE anonymous_storage_global SET conversation_count=MAX(0,conversation_count-1),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=1;
    END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS anonymous_conversation_owner_update AFTER UPDATE OF owner_id,account_id ON conversations
        WHEN OLD.owner_id IS NOT NEW.owner_id OR OLD.account_id IS NOT NEW.account_id BEGIN
        UPDATE anonymous_storage_usage SET conversation_count=MAX(0,conversation_count-1),
            message_count=MAX(0,message_count-(SELECT COUNT(*) FROM messages WHERE conversation_id=OLD.id)),
            text_chars=MAX(0,text_chars-COALESCE((SELECT SUM(length(content)) FROM messages WHERE conversation_id=OLD.id),0)),
            updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE OLD.owner_id IS NOT NULL AND OLD.account_id IS NULL AND owner_id=OLD.owner_id;
        UPDATE anonymous_storage_global SET conversation_count=MAX(0,conversation_count-1),
            message_count=MAX(0,message_count-(SELECT COUNT(*) FROM messages WHERE conversation_id=OLD.id)),
            text_chars=MAX(0,text_chars-COALESCE((SELECT SUM(length(content)) FROM messages WHERE conversation_id=OLD.id),0)),
            updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE OLD.owner_id IS NOT NULL AND OLD.account_id IS NULL AND id=1;
        INSERT INTO anonymous_storage_usage(owner_id,conversation_count,message_count,text_chars,updated_at)
            SELECT NEW.owner_id,1,(SELECT COUNT(*) FROM messages WHERE conversation_id=NEW.id),
            COALESCE((SELECT SUM(length(content)) FROM messages WHERE conversation_id=NEW.id),0),strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE NEW.owner_id IS NOT NULL AND NEW.account_id IS NULL
            ON CONFLICT(owner_id) DO UPDATE SET conversation_count=conversation_count+1,
            message_count=message_count+excluded.message_count,text_chars=text_chars+excluded.text_chars,updated_at=excluded.updated_at;
        UPDATE anonymous_storage_global SET conversation_count=conversation_count+1,
            message_count=message_count+(SELECT COUNT(*) FROM messages WHERE conversation_id=NEW.id),
            text_chars=text_chars+COALESCE((SELECT SUM(length(content)) FROM messages WHERE conversation_id=NEW.id),0),
            updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE NEW.owner_id IS NOT NULL AND NEW.account_id IS NULL AND id=1;
        UPDATE anonymous_message_usage_map SET owner_id=NEW.owner_id WHERE conversation_id=NEW.id AND NEW.owner_id IS NOT NULL AND NEW.account_id IS NULL;
        DELETE FROM anonymous_message_usage_map WHERE conversation_id=NEW.id AND (NEW.owner_id IS NULL OR NEW.account_id IS NOT NULL);
    END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS anonymous_message_insert AFTER INSERT ON messages
        WHEN EXISTS(SELECT 1 FROM conversations c WHERE c.id=NEW.conversation_id AND c.owner_id IS NOT NULL AND c.account_id IS NULL) BEGIN
        INSERT OR REPLACE INTO anonymous_message_usage_map(message_id,conversation_id,owner_id,text_chars)
            SELECT NEW.id,NEW.conversation_id,owner_id,length(NEW.content) FROM conversations WHERE id=NEW.conversation_id;
        UPDATE anonymous_storage_usage SET message_count=message_count+1,text_chars=text_chars+length(NEW.content),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE owner_id=(SELECT owner_id FROM conversations WHERE id=NEW.conversation_id);
        UPDATE anonymous_storage_global SET message_count=message_count+1,text_chars=text_chars+length(NEW.content),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=1;
    END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS anonymous_message_delete AFTER DELETE ON messages
        WHEN EXISTS(SELECT 1 FROM anonymous_message_usage_map WHERE message_id=OLD.id) BEGIN
        UPDATE anonymous_storage_usage SET message_count=MAX(0,message_count-1),text_chars=MAX(0,text_chars-(SELECT text_chars FROM anonymous_message_usage_map WHERE message_id=OLD.id)),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE owner_id=(SELECT owner_id FROM anonymous_message_usage_map WHERE message_id=OLD.id);
        UPDATE anonymous_storage_global SET message_count=MAX(0,message_count-1),text_chars=MAX(0,text_chars-(SELECT text_chars FROM anonymous_message_usage_map WHERE message_id=OLD.id)),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=1;
        DELETE FROM anonymous_message_usage_map WHERE message_id=OLD.id;
    END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS anonymous_message_owner_update AFTER UPDATE OF conversation_id,content ON messages BEGIN
        UPDATE anonymous_storage_usage SET message_count=MAX(0,message_count-1),text_chars=MAX(0,text_chars-length(OLD.content)),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE owner_id=(SELECT owner_id FROM conversations WHERE id=OLD.conversation_id AND owner_id IS NOT NULL AND account_id IS NULL);
        UPDATE anonymous_storage_global SET message_count=MAX(0,message_count-1),text_chars=MAX(0,text_chars-length(OLD.content)),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE EXISTS(SELECT 1 FROM conversations WHERE id=OLD.conversation_id AND owner_id IS NOT NULL AND account_id IS NULL) AND id=1;
        UPDATE anonymous_storage_usage SET message_count=message_count+1,text_chars=text_chars+length(NEW.content),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE owner_id=(SELECT owner_id FROM conversations WHERE id=NEW.conversation_id AND owner_id IS NOT NULL AND account_id IS NULL);
        UPDATE anonymous_storage_global SET message_count=message_count+1,text_chars=text_chars+length(NEW.content),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
            WHERE EXISTS(SELECT 1 FROM conversations WHERE id=NEW.conversation_id AND owner_id IS NOT NULL AND account_id IS NULL) AND id=1;
        DELETE FROM anonymous_message_usage_map WHERE message_id=NEW.id;
        INSERT INTO anonymous_message_usage_map(message_id,conversation_id,owner_id,text_chars)
            SELECT NEW.id,NEW.conversation_id,owner_id,length(NEW.content) FROM conversations
            WHERE id=NEW.conversation_id AND owner_id IS NOT NULL AND account_id IS NULL;
    END""")


def _v7_cloud_budget_schema(db: sqlite3.Connection) -> None:
    """Version cloud reservation structures; also upgrades pre-ledger tables in place."""
    db.execute("""CREATE TABLE IF NOT EXISTS cloud_budget_daily (
        usage_date TEXT NOT NULL, scope_id TEXT NOT NULL,
        requests INTEGER NOT NULL DEFAULT 0, reserved_usd REAL NOT NULL DEFAULT 0,
        actual_usd REAL NOT NULL DEFAULT 0, PRIMARY KEY(usage_date,scope_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS cloud_budget_reservations (
        id TEXT PRIMARY KEY, usage_date TEXT NOT NULL, owner_id TEXT NOT NULL,
        reserved_usd REAL NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)""")
    reservation_columns = {row[1] for row in db.execute("PRAGMA table_info(cloud_budget_reservations)")}
    for column, declaration in (("ip_scope_id", "TEXT"), ("input_rate", "REAL"),
            ("output_rate", "REAL"), ("pricing_version", "TEXT"), ("pricing_model", "TEXT")):
        if column not in reservation_columns:
            db.execute(f"ALTER TABLE cloud_budget_reservations ADD COLUMN {column} {declaration}")
    db.execute("""CREATE TABLE IF NOT EXISTS cloud_active_requests (
        id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, expires_at TEXT NOT NULL)""")
    active_columns = {row[1] for row in db.execute("PRAGMA table_info(cloud_active_requests)")}
    if "ip_scope_id" not in active_columns:
        db.execute("ALTER TABLE cloud_active_requests ADD COLUMN ip_scope_id TEXT")
    db.execute("CREATE INDEX IF NOT EXISTS cloud_budget_daily_scope_idx ON cloud_budget_daily(usage_date,scope_id)")
    db.execute("CREATE INDEX IF NOT EXISTS cloud_budget_reservations_status_idx ON cloud_budget_reservations(status,created_at)")
    db.execute("CREATE INDEX IF NOT EXISTS cloud_active_requests_expiry_idx ON cloud_active_requests(expires_at)")


def _v8_conversation_retention_safety(db: sqlite3.Connection) -> None:
    """Add explicit retention classification; historical ownerless rows stay unknown."""
    columns = _columns(db, "conversations")
    if "retention_class" not in columns:
        db.execute("ALTER TABLE conversations ADD COLUMN retention_class TEXT NOT NULL DEFAULT 'legacy_unknown' CHECK(retention_class IN ('anonymous','account','legacy_unknown'))")
    if "last_activity_at" not in columns:
        db.execute("ALTER TABLE conversations ADD COLUMN last_activity_at TEXT")
    # Account-linked records have an unambiguous durable owner. No ownerless row
    # is inferred to be anonymous, regardless of owner_id or legacy timestamps.
    db.execute("UPDATE conversations SET retention_class='account' WHERE account_id IS NOT NULL AND retention_class='legacy_unknown'")
    db.execute("CREATE INDEX IF NOT EXISTS conversations_retention_activity_idx ON conversations(retention_class,last_activity_at)")
    db.execute("""CREATE TABLE IF NOT EXISTS conversation_activity_leases (
        conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
        principal_type TEXT NOT NULL CHECK(principal_type IN ('anonymous','account')),
        principal_id TEXT NOT NULL, lease_until TEXT NOT NULL, created_at TEXT NOT NULL)""")
    db.execute("CREATE INDEX IF NOT EXISTS conversation_activity_lease_expiry_idx ON conversation_activity_leases(lease_until)")
    db.execute("""CREATE TABLE IF NOT EXISTS data_deletion_tombstones (
        object_type TEXT NOT NULL CHECK(object_type IN ('conversation','account')),
        object_id TEXT NOT NULL, deleted_at TEXT NOT NULL, policy_version TEXT NOT NULL,
        PRIMARY KEY(object_type,object_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS account_deletion_requests (
        account_id TEXT PRIMARY KEY, requested_at TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','purging','complete','failed')),
        updated_at TEXT NOT NULL, failure_code TEXT)""")
    # Replace the v3 conversation triggers so explicit new anonymous records do
    # not enter legacy quarantine. Historical unknown rows remain quarantined.
    for suffix in ("insert", "ownership_update", "delete"):
        db.execute(f"DROP TRIGGER IF EXISTS quarantine_conversations_{suffix}")
    stamp = "strftime('%Y-%m-%dT%H:%M:%fZ','now')"
    db.execute(f"""CREATE TRIGGER quarantine_conversations_insert AFTER INSERT ON conversations
        WHEN NEW.retention_class='legacy_unknown' BEGIN
        INSERT OR IGNORE INTO legacy_data_quarantine(object_type,object_id,reason,quarantined_at)
        VALUES('conversation',CAST(NEW.id AS TEXT),'ambiguous legacy ownership; inaccessible pending explicit review',{stamp}); END""")
    db.execute(f"""CREATE TRIGGER quarantine_conversations_ownership_update AFTER UPDATE OF account_id,retention_class ON conversations BEGIN
        DELETE FROM legacy_data_quarantine WHERE object_type='conversation' AND object_id=CAST(NEW.id AS TEXT);
        INSERT OR IGNORE INTO legacy_data_quarantine(object_type,object_id,reason,quarantined_at)
        SELECT 'conversation',CAST(NEW.id AS TEXT),'ambiguous legacy ownership; inaccessible pending explicit review',{stamp}
        WHERE NEW.retention_class='legacy_unknown'; END""")
    db.execute("""CREATE TRIGGER quarantine_conversations_delete AFTER DELETE ON conversations BEGIN
        DELETE FROM legacy_data_quarantine WHERE object_type='conversation' AND object_id=CAST(OLD.id AS TEXT);
    END""")


MIGRATIONS = (
    Migration(1, "core_data_baseline", _checksum(_v1_core_schema), _v1_core_schema),
    Migration(2, "phase1_anonymous_ownership", _checksum(_v2_phase1_ownership_and_anonymous_sessions), _v2_phase1_ownership_and_anonymous_sessions),
    Migration(3, "durable_account_schema_and_legacy_quarantine", _checksum(_v3_durable_account_schema), _v3_durable_account_schema),
    Migration(4, "google_oidc_one_time_transactions", _checksum(_v4_google_oidc_transactions), _v4_google_oidc_transactions),
    Migration(5, "email_auth_throttling", _checksum(_v5_email_auth_throttling), _v5_email_auth_throttling),
    Migration(6, "durable_security_quotas", _checksum(_v6_durable_security_quotas), _v6_durable_security_quotas),
    Migration(7, "versioned_cloud_budget_schema", _checksum(_v7_cloud_budget_schema), _v7_cloud_budget_schema),
    Migration(8, "conversation_retention_and_deletion_safety", _checksum(_v8_conversation_retention_safety), _v8_conversation_retention_safety),
)

# A separately configured budget database has an independent migration ledger.
# Its first revision is the same immutable table definition used by app revision 7.
CLOUD_BUDGET_MIGRATIONS = (
    Migration(1, "cloud_budget_schema", _checksum(_v7_cloud_budget_schema), _v7_cloud_budget_schema),
)

