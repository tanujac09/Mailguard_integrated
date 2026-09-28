import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from part3 import db, ingest, correlate, cluster, explain, ledger, demo_data, dossier, actions, stix_export

@pytest.fixture()
def loaded():
    conn = db.connect()
    ids = [ingest.ingest_bundle(conn, b, raw_bytes=raw) for b, raw in demo_data.make_demo()]
    correlate.run(conn); camps = cluster.run(conn)
    return conn, ids, camps

def _campaign_of(conn, e):
    r = conn.execute("SELECT campaign_id FROM campaign_members WHERE email_id=?", (e,)).fetchone()
    return r[0] if r else None

def test_all_15_phishing_emails_in_one_campaign(loaded):
    conn, ids, _ = loaded
    assert len({_campaign_of(conn, e) for e in ids[:15]}) == 1
    assert _campaign_of(conn, ids[0]) is not None

def test_shared_ip_decoys_not_in_phishing_campaign(loaded):
    conn, ids, _ = loaded
    d = explain.why_linked(conn, ids[0], ids[15])
    assert d is None or d["decision"] == "rejected"
    assert _campaign_of(conn, ids[15]) != _campaign_of(conn, ids[0])

def test_unrelated_benign_mail_not_grouped(loaded):
    conn, ids, _ = loaded
    assert all(_campaign_of(conn, e) is None for e in ids[18:])

def test_hard_link_explanation(loaded):
    conn, ids, _ = loaded
    d = explain.why_linked(conn, ids[0], ids[1])
    assert d["decision"] == "linked" and d["hard_signals"]

def test_ingest_is_idempotent_and_hash_checked():
    conn = db.connect(); b, raw = demo_data.make_demo()[0]
    assert ingest.ingest_bundle(conn, b, raw_bytes=raw) == ingest.ingest_bundle(conn, b, raw_bytes=raw)
    with pytest.raises(ValueError):
        ingest.ingest_bundle(db.connect(), b, raw_bytes=raw + b"x")

def test_ledger_detects_tampering(loaded):
    conn, _, _ = loaded
    ev = conn.execute("SELECT evidence_id FROM artifacts LIMIT 1").fetchone()[0]
    assert ledger.verify(conn, ev) == (True, None)
    conn.execute("UPDATE custody_events SET detail='{}' WHERE evidence_id=? AND seq=2", (ev,))
    ok, bad = ledger.verify(conn, ev)
    assert not ok and bad == 2

def test_dossier_generated_and_export_recorded(loaded, tmp_path):
    import hashlib
    conn, ids, _ = loaded
    out = str(tmp_path / "d.pdf")
    res = dossier.generate(conn, ids[0], out)
    assert hashlib.sha256(open(out, "rb").read()).hexdigest() == res["sha256"]
    ev = "E-" + ids[0][4:]
    assert conn.execute("SELECT COUNT(*) FROM custody_events WHERE evidence_id=? AND type='EXPORTED'", (ev,)).fetchone()[0] == 1
    assert ledger.verify(conn, ev) == (True, None)

def test_manual_link_then_reject_changes_campaign(loaded):
    conn, ids, _ = loaded
    phish, bakery = ids[0], ids[15]
    actions.record_link_action(conn, "analyst.a", "confirm_link", phish, bakery, "Analyst believes same operator (test)")
    cluster.run(conn)
    assert _campaign_of(conn, phish) == _campaign_of(conn, bakery)
    assert explain.why_linked(conn, phish, bakery)["analyst_status"] == "confirmed"
    actions.record_link_action(conn, "analyst.a", "reject_link", phish, bakery, "Checked: unrelated shared host")
    cluster.run(conn)
    assert _campaign_of(conn, phish) != _campaign_of(conn, bakery)

def test_actions_survive_recorrelation_and_are_audited(loaded):
    conn, ids, _ = loaded
    actions.record_link_action(conn, "analyst.a", "reject_link", ids[0], ids[1], "test reject")
    correlate.run(conn); cluster.run(conn)
    assert explain.why_linked(conn, ids[0], ids[1])["analyst_status"] == "rejected"
    ev = "E-" + ids[0][4:]
    assert conn.execute("SELECT COUNT(*) FROM custody_events WHERE evidence_id=? AND type='ANNOTATED'", (ev,)).fetchone()[0] == 1
    assert ledger.verify(conn, ev) == (True, None)

def test_campaign_confirmation_persists_after_recluster(loaded):
    conn, ids, _ = loaded
    cid = _campaign_of(conn, ids[0])
    actions.record_campaign_action(conn, "analyst.a", "confirm_campaign", cid, "Reviewed all members")
    cluster.run(conn)
    assert conn.execute("SELECT status FROM campaigns WHERE campaign_id=?", (_campaign_of(conn, ids[0]),)).fetchone()[0] == "confirmed"

def test_comment_required():
    conn = db.connect(); b, raw = demo_data.make_demo()[0]; e = ingest.ingest_bundle(conn, b, raw_bytes=raw)
    with pytest.raises(ValueError):
        actions.record_comment(conn, "a", e, "   ")

def test_dossier_shows_analyst_actions(loaded, tmp_path):
    conn, ids, _ = loaded
    actions.record_comment(conn, "analyst.a", ids[0], "Called supplier: they did not send this")
    out = str(tmp_path / "d.pdf"); dossier.generate(conn, ids[0], out)
    from pypdf import PdfReader
    txt = " ".join(p.extract_text() for p in PdfReader(out).pages)
    assert "Called supplier" in txt

def test_stix_export_roundtrip_and_rules(loaded, tmp_path):
    import json, stix2
    conn, ids, _ = loaded
    cid = _campaign_of(conn, ids[0])
    r = stix_export.export(conn, cid, str(tmp_path / "a.json"))
    parsed = stix2.parse(r["text"], allow_custom=True, version="2.1")     # library validates the whole bundle
    types = [o["type"] for o in json.loads(r["text"])["objects"]]
    assert types.count("observed-data") == 15 and types.count("email-message") == 15
    assert r["indicators"] == 0 and "indicator" not in types              # unreviewed campaign: no indicators
    assert "overdue" not in r["text"]                                      # no email body text exported
    ev = "E-" + ids[0][4:]
    assert conn.execute("SELECT COUNT(*) FROM custody_events WHERE evidence_id=? AND type='EXPORTED'", (ev,)).fetchone()[0] == 1
    assert ledger.verify(conn, ev) == (True, None)
    actions.record_campaign_action(conn, "analyst.a", "confirm_campaign", cid, "reviewed")
    r2 = stix_export.export(conn, cid, str(tmp_path / "b.json"), record_export=False)
    objs = json.loads(r2["text"])["objects"]
    pats = [o["pattern"] for o in objs if o["type"] == "indicator"]
    assert r2["indicators"] == len(pats) > 0
    assert not any("ipv4-addr" in p for p in pats)                         # shared IPs never become indicators
    ids1 = {o["id"] for o in json.loads(r["text"])["objects"] if o["type"] in ("campaign", "observed-data")}
    assert ids1 <= {o["id"] for o in objs}                                 # stable IDs across re-export
