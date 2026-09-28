"""Turn one Part 1 + Part 2 analysis bundle into evidence, entities and graph edges."""
import hashlib, json, os
from urllib.parse import urlparse
from . import ledger

REQUIRED = ["artifact", "email", "part1", "part2"]

def _entity(conn, kind, value):
    conn.execute("INSERT OR IGNORE INTO entities (kind, value) VALUES (?,?)", (kind, value))
    return conn.execute("SELECT entity_id FROM entities WHERE kind=? AND value=?", (kind, value)).fetchone()[0]

def _edge(conn, etype, fk, fid, tk, tid, family, strength, source, source_record, observed_at, evidence_id, details=None):
    conn.execute("INSERT INTO relationships (type, from_kind, from_id, to_kind, to_id, family, strength, confidence, "
                 "method, source, source_record, observed_at, evidence_id, details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (etype, fk, str(fid), tk, str(tid), family, strength, 1.0 if family == "observed" else None,
                  "direct_read" if family == "observed" else "enrichment", source, source_record, observed_at,
                  evidence_id, json.dumps(details or {})))

def ingest_bundle(conn, bundle, raw_bytes=None, originals_dir=None, actor="part3.ingest"):
    for k in REQUIRED:
        if k not in bundle:
            raise ValueError("bundle missing key: %s" % k)
    art, em, p1, p2 = bundle["artifact"], bundle["email"], bundle["part1"], bundle["part2"]
    sha = art["sha256"].lower()
    if raw_bytes is not None and hashlib.sha256(raw_bytes).hexdigest() != sha:
        raise ValueError("SHA-256 in bundle does not match the file bytes")
    email_id, artifact_id, evidence_id = "EML-" + sha[:12], "ART-" + sha[:12], "E-" + sha[:12]
    if conn.execute("SELECT 1 FROM emails WHERE email_id=?", (email_id,)).fetchone():
        return email_id  # already ingested (idempotent)
    ts = art.get("collected_at")
    path = None
    if raw_bytes is not None and originals_dir:
        os.makedirs(originals_dir, exist_ok=True)
        path = os.path.join(originals_dir, sha + ".eml")
        if not os.path.exists(path):
            with open(path, "wb") as f: f.write(raw_bytes)
            os.chmod(path, 0o444)  # original is read-only
    conn.execute("INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?)",
                 (artifact_id, evidence_id, art.get("filename"), sha, art.get("size_bytes"), ts, art.get("source", "upload"), path))
    from_addr = em["from_addr"].lower(); from_domain = from_addr.split("@")[-1]
    conn.execute("INSERT INTO emails VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (email_id, artifact_id, em.get("message_id"), em["received_at"], em.get("subject"),
                  em.get("body_norm", ""), from_addr, from_domain, p2.get("risk_score"), json.dumps(bundle)))
    ledger.append(conn, evidence_id, "COLLECTED", actor, {"filename": art.get("filename")}, ts)
    ledger.append(conn, evidence_id, "HASHED", actor, {"sha256": sha, "algorithm": "SHA-256"}, ts)
    ledger.append(conn, evidence_id, "PARSED", "part1", {"spf": p1.get("spf"), "dkim": p1.get("dkim"), "dmarc": p1.get("dmarc")}, ts)
    ledger.append(conn, evidence_id, "ANALYZED", "part2", {"risk_score": p2.get("risk_score")}, ts)

    src = "bundle:%s" % email_id
    obs = em["received_at"]
    a = _entity(conn, "address", from_addr); d = _entity(conn, "domain", from_domain)
    _edge(conn, "SENT_FROM", "Email", email_id, "address", a, "observed", "hard", "part1", src + "#from", obs, evidence_id)
    _edge(conn, "BELONGS_TO", "address", a, "domain", d, "observed", "hard", "part1", src + "#from", obs, evidence_id)
    ip = p1.get("trust_boundary_ip")
    if ip:
        i = _entity(conn, "ip", ip)
        _edge(conn, "ORIGINATED_AT", "Email", email_id, "ip", i, "observed", "medium", "part1", src + "#relay", obs, evidence_id)
        if p2.get("asn"):
            n = _entity(conn, "asn", "AS%s" % p2["asn"])
            _edge(conn, "BELONGS_TO_ASN", "ip", i, "asn", n, "enriched", "soft", "part2", src + "#asn", obs, evidence_id,
                  {"org": p2.get("asn_org")})
    for u in p2.get("urls", []):
        ue = _entity(conn, "url", u["url"])
        _edge(conn, "CONTAINS_URL", "Email", email_id, "url", ue, "observed", "hard", "part2", src + "#url", obs, evidence_id)
        fd = u.get("final_domain") or urlparse(u.get("final_url", u["url"])).hostname
        if fd:
            de = _entity(conn, "domain", fd)
            _edge(conn, "USES_DOMAIN", "url", ue, "domain", de, "observed", "hard", "part2", src + "#redirect", obs, evidence_id)
    for at in p2.get("attachments", []):
        h = _entity(conn, "hash", at["sha256"].lower())
        _edge(conn, "HAS_ATTACHMENT", "Email", email_id, "hash", h, "observed", "hard", "part2", src + "#attachment", obs, evidence_id,
              {"filename": at.get("filename")})
    ledger.append(conn, evidence_id, "INGESTED", actor, {"email_id": email_id}, ts)
    conn.commit()
    return email_id
