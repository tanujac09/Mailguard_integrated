import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY, evidence_id TEXT, filename TEXT, sha256 TEXT NOT NULL,
  size_bytes INTEGER, collected_at TEXT, source TEXT, storage_path TEXT);
CREATE TABLE IF NOT EXISTS emails (
  email_id TEXT PRIMARY KEY, artifact_id TEXT, message_id TEXT, received_at TEXT, subject TEXT,
  body_norm TEXT, from_addr TEXT, from_domain TEXT, risk_score REAL, raw_bundle TEXT);
CREATE TABLE IF NOT EXISTS entities (
  entity_id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value TEXT NOT NULL,
  UNIQUE(kind, value));
CREATE TABLE IF NOT EXISTS relationships (
  rel_id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL,
  from_kind TEXT, from_id TEXT, to_kind TEXT, to_id TEXT,
  family TEXT, strength TEXT, confidence REAL, method TEXT, source TEXT, source_record TEXT,
  observed_at TEXT, evidence_id TEXT, details TEXT, analyst_status TEXT DEFAULT 'auto');
CREATE INDEX IF NOT EXISTS ix_rel_type ON relationships(type);
CREATE INDEX IF NOT EXISTS ix_rel_from ON relationships(from_kind, from_id);
CREATE TABLE IF NOT EXISTS campaigns (
  campaign_id TEXT PRIMARY KEY, created_at TEXT, status TEXT, algorithm_version TEXT,
  size INTEGER, notes TEXT);
CREATE TABLE IF NOT EXISTS campaign_members (
  campaign_id TEXT, email_id TEXT, confidence REAL, top_links TEXT,
  PRIMARY KEY (campaign_id, email_id));
CREATE TABLE IF NOT EXISTS analyst_actions (
  action_id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, analyst TEXT NOT NULL, action TEXT NOT NULL,
  target_type TEXT NOT NULL, target_id TEXT NOT NULL, target_id2 TEXT, comment TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS custody_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id TEXT NOT NULL, seq INTEGER NOT NULL,
  type TEXT NOT NULL, actor TEXT NOT NULL, ts TEXT NOT NULL, detail TEXT,
  prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL, UNIQUE(evidence_id, seq));
"""

def connect(path=":memory:", check_same_thread=True):
    conn = sqlite3.connect(path, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn
