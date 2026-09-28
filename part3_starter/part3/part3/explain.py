"""'Why are these emails linked?' and campaign summaries."""
import json

def why_linked(conn, a, b):
    from . import actions
    r = conn.execute("SELECT type, confidence, strength, method, details, analyst_status FROM relationships WHERE type IN ('LINKED_TO','CANDIDATE_REJECTED') "
                     "AND ((from_id=? AND to_id=?) OR (from_id=? AND to_id=?))", (a, b, b, a)).fetchone()
    last = actions.last_link_action(conn, a, b)
    if not r:
        return {"decision": "no_link", "score": 0.0, "reason": "no shared signals recorded", "hard_signals": [], "signals": {}, "type": None,
                "method": "-", "analyst_status": "confirmed" if last and last["action"] == "confirm_link" else "auto", "analyst": last} if last else None
    d = json.loads(r["details"]); d["type"] = r["type"]; d["method"] = r["method"]
    d["analyst_status"] = r["analyst_status"]; d["analyst"] = last
    return d

def format_why(a, b, d):
    if d is None:
        return "%s and %s: no link and no notable shared signals recorded." % (a, b)
    lines = ["%s <-> %s: %s (score %.2f, %s)" % (a, b, d["decision"].upper(), d["score"], d["reason"])]
    for k, v in sorted(d["signals"].items(), key=lambda kv: -kv[1]["contribution"]):
        if v["value"] > 0:
            lines.append("   %-10s value=%.2f x weight %.2f = %.3f" % (k, v["value"], v["weight"], v["contribution"]))
    if d["hard_signals"]:
        lines.append("   HARD: " + "; ".join(d["hard_signals"]))
    if d.get("analyst"):
        an = d["analyst"]; lines.append("   ANALYST %s (%s, %s): %s" % (an["action"].replace("_link", "").upper(), an["analyst"], an["ts"], an["comment"]))
    lines.append("   (score is an algorithmic assessment, not legal proof; method %s)" % d["method"])
    return "\n".join(lines)

def campaign_summary(conn, campaign_id):
    ids = [r["email_id"] for r in conn.execute("SELECT email_id FROM campaign_members WHERE campaign_id=?", (campaign_id,))]
    counts = {"ip": {}, "domain": {}, "hash": {}}
    for e in ids:
        b = json.loads(conn.execute("SELECT raw_bundle FROM emails WHERE email_id=?", (e,)).fetchone()[0])
        if b["part1"].get("trust_boundary_ip"):
            counts["ip"][b["part1"]["trust_boundary_ip"]] = counts["ip"].get(b["part1"]["trust_boundary_ip"], 0) + 1
        for u in b["part2"].get("urls", []):
            if u.get("final_domain"): counts["domain"][u["final_domain"]] = counts["domain"].get(u["final_domain"], 0) + 1
        for a in b["part2"].get("attachments", []):
            counts["hash"][a["sha256"][:12] + "..."] = counts["hash"].get(a["sha256"][:12] + "...", 0) + 1
    return {"campaign_id": campaign_id, "members": len(ids),
            "shared": {k: sorted(v.items(), key=lambda kv: -kv[1]) for k, v in counts.items()}}

def timeline(conn, campaign_id):
    """Emails and custody events of a campaign's members on one time axis."""
    rows = []
    for m in conn.execute("SELECT e.email_id, e.received_at, e.from_addr, e.subject, a.evidence_id FROM campaign_members c "
                          "JOIN emails e USING (email_id) JOIN artifacts a USING (artifact_id) WHERE c.campaign_id=?", (campaign_id,)):
        rows.append({"time": m["received_at"], "kind": "EMAIL", "item": m["email_id"], "what": "received from %s (%s)" % (m["from_addr"], m["subject"])})
        for ev in conn.execute("SELECT ts, type, actor FROM custody_events WHERE evidence_id=? ORDER BY seq", (m["evidence_id"],)):
            rows.append({"time": ev["ts"], "kind": "CUSTODY", "item": m["evidence_id"], "what": "%s by %s" % (ev["type"], ev["actor"])})
    return sorted(rows, key=lambda r: (r["time"], r["kind"], r["item"]))
