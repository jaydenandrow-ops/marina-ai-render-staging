"""Fail-closed database path checks shared by application and image storage.

This module has no dotenv, database, or application import side effects.
"""
from __future__ import annotations

import os
from pathlib import Path


def validate_test_database_path(
    path: str | Path,
    *,
    environment: str | None = None,
    isolation_root: str | Path | None = None,
    project_root: str | Path,
) -> Path:
    """In test mode, allow SQLite files only below an explicit external temp root."""
    mode = environment if environment is not None else os.getenv("GENESIS_ENV", "")
    target = Path(path).expanduser().resolve(strict=False)
    project = Path(project_root).expanduser().resolve(strict=False)
    if mode != "test":
        return target

    configured_root = isolation_root if isolation_root is not None else os.getenv("MARINA_TEST_ISOLATION_ROOT", "")
    if not str(configured_root).strip():
        raise RuntimeError("Test database isolation root is required.")
    root = Path(configured_root).expanduser().resolve(strict=False)
    if root == project or project in root.parents or root in project.parents:
        raise RuntimeError("Test database isolation root must be separate from the application project.")
    if target == root or root not in target.parents:
        raise RuntimeError("Test database path must be inside the verified temporary isolation root.")
    if target == project / "genesis.db" or project in target.parents:
        raise RuntimeError("Test database path resolves into the application project.")
    return target


def validate_test_database_configuration(
    app_path: str | Path,
    budget_path: str | Path,
    *,
    environment: str | None = None,
    isolation_root: str | Path | None = None,
    project_root: str | Path,
) -> tuple[Path, Path]:
    """Validate both persistent SQLite paths before imports or I/O can use them."""
    mode = environment if environment is not None else os.getenv("GENESIS_ENV", "")
    if mode != "test":
        return (Path(app_path).expanduser().resolve(strict=False),
                Path(budget_path).expanduser().resolve(strict=False))
    app = validate_test_database_path(app_path, environment=mode,
        isolation_root=isolation_root, project_root=project_root)
    budget = validate_test_database_path(budget_path, environment=mode,
        isolation_root=isolation_root, project_root=project_root)
    return app, budget
