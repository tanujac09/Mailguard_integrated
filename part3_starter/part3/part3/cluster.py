"""Form campaigns from strong links: connected components, checked by Louvain community detection."""
import json
import networkx as nx
from . import ledger, actions

VERSION = "cluster-0.1"

def run(conn, ts=None):
    G = nx.Graph()
    G.add_nodes_from(r["email_id"] for r in conn.execute("SELECT email_id FROM emails"))
    for r in conn.execute("SELECT from_id, to_id, confidence, strength, analyst_status FROM relationships WHERE type='LINKED_TO'"):
        if r["analyst_status"] == "rejected":
            continue   # analyst rejected this link
        G.add_edge(r["from_id"], r["to_id"], weight=r["confidence"], hard=(r["strength"] == "hard"))
    for (a, b), act in actions.overrides(conn).items():
        if act == "confirm" and a in G and b in G and not G.has_edge(a, b):
            G.add_edge(a, b, weight=0.8, hard=True)   # analyst-added link
    for t in ("campaigns", "campaign_members"):
        conn.execute("DELETE FROM %s" % t)
    conn.execute("DELETE FROM relationships WHERE type='MEMBER_OF'")
    comps = sorted([c for c in nx.connected_components(G) if len(c) >= 2], key=lambda c: (-len(c), sorted(c)[0]))
    out = []
    for i, comp in enumerate(comps, 1):
        cid = "CMP-%03d" % i
        sub = G.subgraph(comp)
        communities = nx.community.louvain_communities(sub, weight="weight", seed=42)
        notes = "" if len(communities) == 1 else "REVIEW: community detection suggests %d sub-groups; a weak bridge may have merged campaigns" % len(communities)
        conn.execute("INSERT INTO campaigns VALUES (?,?,?,?,?,?)", (cid, ts or ledger.now_iso(), "proposed", VERSION, len(comp), notes))
        for e in sorted(comp):
            links = sorted(((sub[e][n]["weight"], n, sub[e][n]["hard"]) for n in sub[e]), reverse=True)[:3]
            conf = sum(w for w, _, _ in links) / len(links)
            if not any(h for _, _, h in links):
                conf = min(conf, 0.60)   # no hard link among the strongest evidence: cap confidence
            conf = round(conf, 2)
            conn.execute("INSERT INTO campaign_members VALUES (?,?,?,?)",
                         (cid, e, conf, json.dumps([{"email": n, "score": w, "hard": h} for w, n, h in links])))
            conn.execute("INSERT INTO relationships (type, from_kind, from_id, to_kind, to_id, family, strength, confidence, method, source, source_record) "
                         "VALUES ('MEMBER_OF','Email',?,'Campaign',?,'derived','assessment',?,?,?,?)",
                         (e, cid, conf, VERSION, "part3.cluster", "campaign:%s" % cid))
            ev = conn.execute("SELECT a.evidence_id FROM emails m JOIN artifacts a USING (artifact_id) WHERE m.email_id=?", (e,)).fetchone()
            if ev:
                ledger.append(conn, ev[0], "ANALYZED", "part3.cluster", {"campaign": cid, "confidence": conf, "method": VERSION}, ts)
        for rep, status in actions.campaign_statuses(conn):
            if rep in comp:
                conn.execute("UPDATE campaigns SET status=? WHERE campaign_id=?", (status, cid))
        out.append({"campaign_id": cid, "size": len(comp), "notes": notes})
    conn.commit()
    return out
