"""Analyst actions: confirm/reject a link, add a comment, confirm/reject a campaign.
Every action is stored in analyst_actions AND recorded in the custody ledger (ANNOTATED).
The original algorithmic edges are never deleted; an override is a separate, attributed record."""
import json
from . import ledger

LINK_ACTIONS = ("confirm_link", "reject_link")
CAMPAIGN_ACTIONS = {"confirm_campaign": "confirmed", "reject_campaign": "rejected"}

def _need(comment):
    if not (comment or "").strip():
        raise ValueError("a comment is required for every analyst action")
    return comment.strip()

def _evidence_of(conn, email_id):
    r = conn.execute("SELECT a.evidence_id FROM emails e JOIN artifacts a USING (artifact_id) WHERE e.email_id=?", (email_id,)).fetchone()
    if not r:
        raise ValueError("unknown email: %s" % email_id)
    return r[0]

def _log(conn, analyst, action, target, target2, comment, emails):
    conn.execute("INSERT INTO analyst_actions (ts, analyst, action, target_type, target_id, target_id2, comment) VALUES (?,?,?,?,?,?,?)",
                 (ledger.now_iso(), analyst, action, target[0], target[1], target2, comment))
    for e in emails:
        ledger.append(conn, _evidence_of(conn, e), "ANNOTATED", analyst,
                      {"action": action, "target": [target[1]] + ([target2] if target2 else []), "comment": comment[:200]})

def record_link_action(conn, analyst, action, a, b, comment):
    if action not in LINK_ACTIONS: raise ValueError("bad action")
    if a == b: raise ValueError("pick two different emails")
    comment = _need(comment)
    _log(conn, analyst, action, ("link", min(a, b)), max(a, b), comment, [a, b])
    apply_link_status(conn); conn.commit()

def record_comment(conn, analyst, email_id, comment):
    comment = _need(comment)
    _log(conn, analyst, "comment", ("email", email_id), None, comment, [email_id]); conn.commit()

def record_campaign_action(conn, analyst, action, campaign_id, comment):
    if action not in CAMPAIGN_ACTIONS: raise ValueError("bad action")
    comment = _need(comment)
    members = [r[0] for r in conn.execute("SELECT email_id FROM campaign_members WHERE campaign_id=?", (campaign_id,))]
    if not members: raise ValueError("unknown campaign")
    _log(conn, analyst, action, ("campaign", min(members)), None, comment, members)   # keyed by the lowest email id so it survives re-clustering
    conn.execute("UPDATE campaigns SET status=? WHERE campaign_id=?", (CAMPAIGN_ACTIONS[action], campaign_id)); conn.commit()

def overrides(conn):
    """Latest link decision per pair: {(a,b): 'confirm' | 'reject'}."""
    out = {}
    for r in conn.execute("SELECT action, target_id, target_id2 FROM analyst_actions WHERE target_type='link' ORDER BY action_id"):
        out[(r["target_id"], r["target_id2"])] = "confirm" if r["action"] == "confirm_link" else "reject"
    return out

def apply_link_status(conn):
    conn.execute("UPDATE relationships SET analyst_status='auto' WHERE type IN ('LINKED_TO','CANDIDATE_REJECTED')")
    for (a, b), act in overrides(conn).items():
        conn.execute("UPDATE relationships SET analyst_status=? WHERE type IN ('LINKED_TO','CANDIDATE_REJECTED') AND "
                     "((from_id=? AND to_id=?) OR (from_id=? AND to_id=?))", ("confirmed" if act == "confirm" else "rejected", a, b, b, a))

def campaign_statuses(conn):
    """Ordered list of (representative_email_id, status); the last match wins."""
    return [(r["target_id"], CAMPAIGN_ACTIONS[r["action"]]) for r in
            conn.execute("SELECT action, target_id FROM analyst_actions WHERE target_type='campaign' ORDER BY action_id")]

def last_link_action(conn, a, b):
    r = conn.execute("SELECT ts, analyst, action, comment FROM analyst_actions WHERE target_type='link' AND target_id=? AND target_id2=? "
                     "ORDER BY action_id DESC LIMIT 1", (min(a, b), max(a, b))).fetchone()
    return dict(r) if r else None

def for_email(conn, email_id):
    """All analyst actions relevant to one email (its links, its comments, its campaign)."""
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM analyst_actions WHERE (target_type='email' AND target_id=?) OR (target_type='link' AND (target_id=? OR target_id2=?)) ORDER BY action_id",
        (email_id, email_id, email_id))]
    camp = conn.execute("SELECT campaign_id FROM campaign_members WHERE email_id=?", (email_id,)).fetchone()
    if camp:
        members = {r[0] for r in conn.execute("SELECT email_id FROM campaign_members WHERE campaign_id=?", (camp[0],))}
        rows += [dict(r) for r in conn.execute("SELECT * FROM analyst_actions WHERE target_type='campaign' ORDER BY action_id") if r["target_id"] in members]
    return sorted(rows, key=lambda r: r["action_id"])
