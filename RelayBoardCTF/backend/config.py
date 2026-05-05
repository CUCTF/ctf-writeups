import os
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent


class Config:
    SECRET_KEY = os.environ.get(
        "RELAYBOARD_SECRET",
        "relayboard-dev-secret-please-rotate",
    )
    DB_PATH = PROJECT_ROOT / "relayboard.db"
    SNIPPET_DIR = PACKAGE_ROOT / "snippets"
    FLAG_VALUE = os.environ.get(
        "RELAYBOARD_FLAG",
        "flag{night_shift_packets_need_real_boundaries}",
    )
