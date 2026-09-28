"""Hash-chained custody ledger. H0 = SHA256("GENESIS"); Hn = SHA256(canonical(event_n) + H(n-1))."""
import hashlib, json
from datetime import datetime, timezone

GENESIS = hashlib.sha256(b"GENESIS").hexdigest()

def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _hash(event, prev_hash):
    return hashlib.sha256((canon(event) + prev_hash).encode("utf-8")).hexdigest()

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def append(conn, evidence_id, etype, actor, detail=None, ts=None):
    row = conn.execute("SELECT seq, event_hash FROM custody_events WHERE evidence_id=? ORDER BY seq DESC LIMIT 1",
                       (evidence_id,)).fetchone()
    seq, prev = (row["seq"] + 1, row["event_hash"]) if row else (1, GENESIS)
    event = {"seq": seq, "evidence_id": evidence_id, "type": etype, "actor": actor,
             "ts": ts or now_iso(), "detail": detail or {}}
    h = _hash(event, prev)
    conn.execute("INSERT INTO custody_events (evidence_id, seq, type, actor, ts, detail, prev_hash, event_hash) "
                 "VALUES (?,?,?,?,?,?,?,?)",
                 (evidence_id, seq, etype, actor, event["ts"], canon(event["detail"]), prev, h))
    return h

def verify(conn, evidence_id):
    """Return (ok, first_bad_seq). Recomputes the whole chain from the start."""
    prev = GENESIS
    rows = conn.execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY seq", (evidence_id,)).fetchall()
    for r in rows:
        event = {"seq": r["seq"], "evidence_id": r["evidence_id"], "type": r["type"], "actor": r["actor"],
                 "ts": r["ts"], "detail": json.loads(r["detail"] or "{}")}
        if r["prev_hash"] != prev or _hash(event, prev) != r["event_hash"]:
            return False, r["seq"]
        prev = r["event_hash"]
    return True, None
