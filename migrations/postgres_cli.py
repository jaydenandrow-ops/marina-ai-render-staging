"""Explicit PostgreSQL fresh-schema apply/readiness command; never loads dotenv."""
from __future__ import annotations

import argparse
import os
import sys

from database_backend import close_postgres_pool, database_url, is_postgres_url
from migrations.postgres import migrate_fresh, verify_ready


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="read-only migration/schema readiness check")
    group.add_argument("--apply-fresh", action="store_true", help="apply schema only to an empty public schema")
    args = parser.parse_args()
    url = database_url()
    if not is_postgres_url(url):
        print("PostgreSQL URL is missing or unsupported; no connection attempted.", file=sys.stderr)
        return 2
    if os.getenv("GENESIS_ENV", "") == "test":
        from database_backend import validate_test_postgres_url
        validate_test_postgres_url(url)
    try:
        result = verify_ready() if args.check else {"database_dialect":"postgresql", "applied_version":migrate_fresh()}
        print("PostgreSQL schema check passed." if args.check else "Fresh PostgreSQL schema applied.")
        print(f"database_dialect={result['database_dialect']} schema_version={result.get('current_version', result.get('applied_version'))}")
        return 0
    except Exception as exc:
        # Do not print DSN, query parameters, provider exceptions, or server text.
        print(f"PostgreSQL migration operation failed ({type(exc).__name__}); inspect protected server logs.", file=sys.stderr)
        return 1
    finally:
        close_postgres_pool()


if __name__ == "__main__":
    raise SystemExit(main())
