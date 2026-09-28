"""End-to-end demo: ingest -> correlate -> cluster -> explain -> custody verify -> tamper test."""
import json, os
from part3 import db, ingest, correlate, cluster, explain, ledger, demo_data

def main(path="data/part3.db"):
    if os.path.exists(path): os.remove(path)
    conn = db.connect(path)
    items = demo_data.make_demo()
    ids = [ingest.ingest_bundle(conn, b, raw_bytes=raw, originals_dir="data/originals") for b, raw in items]
    print("Ingested %d emails" % len(ids))
    print("Correlation:", correlate.run(conn))
    camps = cluster.run(conn)
    print("Campaigns:", camps)
    cid = camps[0]["campaign_id"]
    print(json.dumps(explain.campaign_summary(conn, cid), indent=1))
    a = ids[0]                                   # first campaign email
    b = ids[1]
    print("\n" + explain.format_why(a, b, explain.why_linked(conn, a, b)))
    decoy = ids[15]                              # bakery decoy on the same shared IP
    print("\n" + explain.format_why(a, decoy, explain.why_linked(conn, a, decoy)))
    ev = conn.execute("SELECT evidence_id FROM artifacts LIMIT 1").fetchone()[0]
    print("\nCustody verify:", ledger.verify(conn, ev))
    conn.execute("UPDATE custody_events SET actor='someone-else' WHERE evidence_id=? AND seq=2", (ev,))
    print("After editing event 2:", ledger.verify(conn, ev), "<- tampering detected")
    conn.rollback()

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True); main()
