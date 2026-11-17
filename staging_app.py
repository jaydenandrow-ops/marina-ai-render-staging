"""Basic-auth gate for synthetic-only staging; all non-health paths are locked."""
import os

from main import app as _app
from staging_gate import StagingAccessGate


app = StagingAccessGate(_app, os.getenv("STAGING_BASIC_AUTH_USERNAME", ""),
    os.getenv("STAGING_BASIC_AUTH_PASSWORD", ""))
