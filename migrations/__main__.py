from __future__ import annotations

import argparse
import sqlite3
import sys

from .runner import MigrationError, print_dry_run
from .versions import CLOUD_BUDGET_MIGRATIONS, MIGRATIONS


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only inspection of GENESIS AI SQLite schema revisions.")
    parser.add_argument("--db-path", required=True, help="Explicit database path; no default production path is used.")
    parser.add_argument("--dry-run", action="store_true", help="Read-only schema and pending migration report.")
    parser.add_argument("--budget-db", action="store_true", help="Inspect the independent cloud-budget migration ledger instead of the application schema.")
    args = parser.parse_args()
    if not args.dry_run:
        parser.error("Only --dry-run is available in this operator CLI. Production migrations must be applied using a separately approved, controlled operator procedure.")
    try:
        print_dry_run(args.db_path, migrations=CLOUD_BUDGET_MIGRATIONS if args.budget_db else MIGRATIONS)
        return 0
    except (MigrationError, OSError, sqlite3.Error) as exc:
        print(f"Migration dry-run failed safely: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
