"""Small helpers used by the Streamlit app."""
from . import ingest, correlate, cluster, demo_data

TABLES = ["analyst_actions", "custody_events", "campaign_members", "campaigns", "relationships", "entities", "emails", "artifacts"]

def reset(conn):
    for t in TABLES:
        conn.execute("DELETE FROM %s" % t)
    conn.commit()

def run_all(conn):
    return correlate.run(conn), cluster.run(conn)

def load_demo(conn):
    reset(conn)
    for bundle, raw in demo_data.make_demo():
        ingest.ingest_bundle(conn, bundle, raw_bytes=raw)
    return run_all(conn)

def recluster(conn):
    """Re-form campaigns after an analyst action (keeps overrides and campaign decisions)."""
    return cluster.run(conn)
