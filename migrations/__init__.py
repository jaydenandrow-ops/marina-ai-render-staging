"""Versioned SQLite schema migrations for GENESIS AI.

The migration API is intentionally separate from application request logic. SQLite
is the only supported dialect in this milestone; see MIGRATION_RECOVERY.md before
running a migration against any data-bearing database.
"""

from .runner import CURRENT_VERSION, MigrationError, dry_run, migrate

__all__ = ["CURRENT_VERSION", "MigrationError", "dry_run", "migrate"]
