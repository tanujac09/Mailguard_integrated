"""Pairwise campaign-link scoring with per-signal explanations.

IMPORTANT: the weights below are placeholders. Tune them on labelled data before trusting them.
"""
import json, math, re
from datetime import datetime
from itertools import combinations

VERSION = "corr-0.1"
WEIGHTS = {"infra": 0.25, "url": 0.20, "content": 0.20, "attachment": 0.15, "identity": 0.15, "time": 0.05}
THRESHOLD = 0.55          # minimum score to create a link (tuned on synthetic demo data only: re-tune on real data)
STORE_REJECTED_ABOVE = 0.20   # keep near-misses so the UI can show "why NOT linked"
IP_RARITY_K = 8           # an IP seen in more than K emails counts for less (shared-hosting guard)
TIME_TAU_MIN = 60.0

def _tokens(url):
    t = re.split(r"[^a-z0-9]+", url.lower())
    return {re.sub(r"\d+", "#", x) for x in t if x and x not in ("http", "https", "www")}

def _shingles(text, n=2):
    # digits are normalised to '#', so invoice numbers, dates and amounts do not break near-duplicate matching
    w = re.findall(r"[a-z#]+", re.sub(r"\d+", "#", (text or "").lower()))
    return {" ".join(w[i:i + n]) for i in range(max(0, len(w) - n + 1))}

def _jac(a, b):
    return len(a & b) / len(a | b) if a and b and (a | b) else 0.0

def features(bundle):
    em, p1, p2 = bundle["email"], bundle["part1"], bundle["part2"]
    addr = em["from_addr"].lower()
    return {
        "ip": p1.get("trust_boundary_ip"), "asn": p2.get("asn"),
        "final_domains": {u.get("final_domain") for u in p2.get("urls", []) if u.get("final_domain")},
        "url_tokens": set().union(*[_tokens(u.get("final_url") or u["url"]) for u in p2.get("urls", [])]) if p2.get("urls") else set(),
        "hashes": {a["sha256"].lower() for a in p2.get("attachments", [])},
        "addr": addr, "domain": addr.split("@")[-1], "lookalike": p1.get("lookalike_of"),
        "shingles": _shingles(em.get("body_norm", "")),
        "t": datetime.strptime(em["received_at"], "%Y-%m-%dT%H:%M:%SZ"),
    }

def score_pair(fa, fb, ip_counts):
    s, hard = {}, []
    if fa["ip"] and fa["ip"] == fb["ip"]:
        s["infra"] = min(1.0, IP_RARITY_K / max(1, ip_counts.get(fa["ip"], 1)))   # rarity discount
    elif fa["asn"] and fa["asn"] == fb["asn"]:
        s["infra"] = 0.3
    else:
        s["infra"] = 0.0
    if fa["final_domains"] & fb["final_domains"]:
        s["url"] = 1.0; hard.append("same redirect/landing domain")
    else:
        s["url"] = _jac(fa["url_tokens"], fb["url_tokens"])
    s["content"] = _jac(fa["shingles"], fb["shingles"])
    if fa["hashes"] & fb["hashes"]:
        s["attachment"] = 1.0; hard.append("same attachment SHA-256")
    else:
        s["attachment"] = 0.0
    if fa["addr"] == fb["addr"]:
        s["identity"] = 1.0; hard.append("same sender address")
    elif fa["domain"] == fb["domain"]:
        s["identity"] = 0.8; hard.append("same sender domain")
    elif fa["lookalike"] and fa["lookalike"] == fb["lookalike"]:
        s["identity"] = 0.6
    else:
        s["identity"] = 0.0
    dt = abs((fa["t"] - fb["t"]).total_seconds()) / 60.0
    s["time"] = math.exp(-dt / TIME_TAU_MIN)
    total = sum(WEIGHTS[k] * s[k] for k in WEIGHTS)
    soft_families = [k for k in ("infra", "url", "content", "identity") if s[k] >= 0.5]
    if total < THRESHOLD:
        decision, reason = "rejected", "score below threshold"
    elif hard or len(soft_families) >= 2:
        decision, reason = "linked", "hard link" if hard else "two independent soft signal families"
    else:
        decision, reason = "rejected", "needs corroboration (one soft signal family only)"
    detail = {"score": round(total, 3), "decision": decision, "reason": reason, "hard_signals": hard,
              "signals": {k: {"value": round(s[k], 3), "weight": WEIGHTS[k], "contribution": round(WEIGHTS[k] * s[k], 3)} for k in WEIGHTS}}
    return total, detail

def run(conn):
    rows = conn.execute("SELECT email_id, raw_bundle FROM emails ORDER BY received_at, email_id").fetchall()
    feats = {r["email_id"]: features(json.loads(r["raw_bundle"])) for r in rows}
    ip_counts = {}
    for f in feats.values():
        if f["ip"]: ip_counts[f["ip"]] = ip_counts.get(f["ip"], 0) + 1
    conn.execute("DELETE FROM relationships WHERE type IN ('LINKED_TO','CANDIDATE_REJECTED')")
    linked = rejected = 0
    for a, b in combinations(feats, 2):
        total, d = score_pair(feats[a], feats[b], ip_counts)
        if d["decision"] == "linked":
            linked += 1; typ = "LINKED_TO"
        elif total >= STORE_REJECTED_ABOVE:
            rejected += 1; typ = "CANDIDATE_REJECTED"
        else:
            continue
        strength = "hard" if d["hard_signals"] else "soft"
        conn.execute("INSERT INTO relationships (type, from_kind, from_id, to_kind, to_id, family, strength, confidence, method, "
                     "source, source_record, observed_at, evidence_id, details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (typ, "Email", a, "Email", b, "derived", strength, round(total, 3), VERSION, "part3.correlate",
                      "pair:%s|%s" % (a, b), None, None, json.dumps(d)))
    from . import actions
    actions.apply_link_status(conn)
    conn.commit()
    return {"emails": len(feats), "linked": linked, "rejected_near_misses": rejected}
