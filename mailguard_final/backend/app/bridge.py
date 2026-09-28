"""
bridge.py — the glue between mailguard_final and part3_starter.

Call `send_to_part3(result, filename, raw_bytes)` right after
`pipeline.run_pipeline()` succeeds (see INTEGRATION.md for exactly
where). Nothing here is wired in automatically — you decide when
to call it.

Two modes, controlled by the PART3_MODE env var:

  PART3_MODE=file  (default)
    Writes each bundle as JSON into PART3_BUNDLE_DIR. Part3's own
    Streamlit app (app.py) already has a file-uploader for exactly
    this format — drag the files in there, no part3 code changes
    needed. Safest option: mailguard_final and part3_starter never
    need to be on the same Python path or share a database.

  PART3_MODE=live
    Imports part3_starter directly and calls its ingest_bundle()
    against a shared SQLite file (PART3_DB_PATH), so every upload
    auto-populates part3's graph with no manual step. Only imports
    part3 when this mode is actually used, so "file" mode never
    requires part3_starter to be installed/importable at all.

Does not modify part3_starter's ingest.py/db.py in any way — it
only calls the public functions they already expose.
"""
import json
import os
import sys
from pathlib import Path

from .adapters import build_bundle

PART3_MODE = os.getenv("PART3_MODE", "file")
PART3_BUNDLE_DIR = os.getenv("PART3_BUNDLE_DIR", "./part3_bundles")
PART3_DB_PATH = os.getenv("PART3_DB_PATH", "./part3.db")
PART3_PACKAGE_DIR = os.getenv("PART3_PACKAGE_DIR", "../part3_starter/part3")


def _send_file(bundle: dict) -> dict:
    Path(PART3_BUNDLE_DIR).mkdir(parents=True, exist_ok=True)
    out_path = Path(PART3_BUNDLE_DIR) / f"{bundle['artifact']['sha256']}.json"
    with open(out_path, "w") as f:
        json.dump(bundle, f, indent=2)
    return {"mode": "file", "path": str(out_path)}


def _send_live(bundle: dict, raw_bytes: bytes) -> dict:
    if PART3_PACKAGE_DIR not in sys.path:
        sys.path.insert(0, PART3_PACKAGE_DIR)
    from part3 import db as part3_db          # part3_starter's own code, untouched
    from part3 import ingest as part3_ingest  # part3_starter's own code, untouched

    conn = part3_db.connect(PART3_DB_PATH, check_same_thread=False)
    email_id = part3_ingest.ingest_bundle(conn, bundle, raw_bytes=raw_bytes)
    return {"mode": "live", "email_id": email_id}


def send_to_part3(result: dict, filename: str, raw_bytes: bytes) -> dict:
    """
    result: the full dict returned by pipeline.run_pipeline()
            i.e. {"parsed": ..., "steps": [...], "fusion": {...}}
    """
    bundle = build_bundle(result["parsed"], result["steps"], result["fusion"], filename, raw_bytes)

    if PART3_MODE == "file":
        outcome = _send_file(bundle)
    elif PART3_MODE == "live":
        outcome = _send_live(bundle, raw_bytes)
    else:
        raise ValueError(f"Unknown PART3_MODE: {PART3_MODE!r} (expected 'file' or 'live')")

    outcome["bundle"] = bundle
    return outcome
