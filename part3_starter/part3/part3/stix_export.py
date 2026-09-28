"""Export a campaign as a STIX 2.1 bundle.

Design choices (see the research guide):
- Observations (what we saw in emails) become observed-data + cyber-observables.
- The campaign is our ASSESSMENT: it carries the algorithmic confidence and links back to evidence IDs.
- Indicators are created ONLY for analyst-confirmed campaigns, and only for landing domains and attachment hashes.
  Shared IPs are never turned into indicators (a shared IP can be shared hosting).
- No email body text is exported (privacy).
"""
import hashlib, json, uuid
from datetime import datetime, timezone
import stix2
from . import ledger

NS = uuid.UUID("6f1c2f2e-3a54-4a5e-9c53-5d0f3e5b7a11")   # fixed namespace, so re-exports keep the same object IDs

def _id(kind, key):
    return "%s--%s" % (kind, uuid.uuid5(NS, "%s|%s" % (kind, key)))

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def _iso(t):
    return t.replace("Z", ".000Z") if t and "." not in t else t

def build_bundle(conn, campaign_id, now=None):
    now = now or _now()
    camp = conn.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
    if not camp:
        raise ValueError("unknown campaign")
    members = conn.execute("SELECT m.email_id, m.confidence, e.raw_bundle, a.evidence_id, a.sha256 FROM campaign_members m "
                           "JOIN emails e USING (email_id) JOIN artifacts a USING (artifact_id) WHERE m.campaign_id=? ORDER BY m.email_id", (campaign_id,)).fetchall()
    ident = stix2.Identity(id=_id("identity", "part3"), name="SIH 2026 PS106 Part 3 prototype", identity_class="system",
                           created=now, modified=now)
    common = dict(created_by_ref=ident.id, created=now, modified=now, allow_custom=True)
    objs, seen = [ident], {}
    def add(o):
        if o.id not in seen: seen[o.id] = o; objs.append(o)
        return seen[o.id]
    counts = {"domain": {}, "ip": {}, "hash": {}}
    obs_list, times = [], []
    for m in members:
        b = json.loads(m["raw_bundle"]); em, p1, p2 = b["email"], b["part1"], b["part2"]
        refs = []
        addr = add(stix2.EmailAddress(value=em["from_addr"])); refs.append(addr.id)
        msg = add(stix2.EmailMessage(id=_id("email-message", m["email_id"]), is_multipart=False, date=_iso(em["received_at"]), from_ref=addr.id, subject=em.get("subject"),
                                     message_id=em.get("message_id"))); refs.append(msg.id)
        ip = p1.get("trust_boundary_ip")
        if ip:
            kw = {}
            if p2.get("asn"):
                asn = add(stix2.AutonomousSystem(number=int(p2["asn"]), name=p2.get("asn_org") or "unknown")); kw["belongs_to_refs"] = [asn.id]; refs.append(asn.id)
            ipo = add((stix2.IPv6Address if ":" in ip else stix2.IPv4Address)(value=ip, **kw)); refs.append(ipo.id)
            counts["ip"].setdefault(ip, []).append(ipo.id)
        for u in p2.get("urls", []):
            refs.append(add(stix2.URL(value=u.get("final_url") or u["url"])).id)
            if u.get("final_domain"):
                d = add(stix2.DomainName(value=u["final_domain"])); refs.append(d.id)
                counts["domain"].setdefault(u["final_domain"], []).append(d.id)
        for at in p2.get("attachments", []):
            f = add(stix2.File(hashes={"SHA-256": at["sha256"].lower()}, name=at.get("filename"))); refs.append(f.id)
            counts["hash"].setdefault(at["sha256"].lower(), []).append(f.id)
        t = _iso(em["received_at"]); times.append(t)
        obs = stix2.ObservedData(id=_id("observed-data", m["email_id"]), first_observed=t, last_observed=t, number_observed=1,
                                 object_refs=list(dict.fromkeys(refs)), x_part3_evidence_id=m["evidence_id"], x_part3_artifact_sha256=m["sha256"], **common)
        obs_list.append((obs, m)); objs.append(obs)
    mean = sum(m["confidence"] for _, m in obs_list) / len(obs_list)
    campaign = stix2.Campaign(id=_id("campaign", campaign_id), name=campaign_id, first_seen=min(times), last_seen=max(times),
                              description="Group of %d emails correlated by Part 3. This is an algorithmic assessment, not proof of attribution." % len(members),
                              confidence=int(round(mean * 100)),
                              x_part3_status=camp["status"], x_part3_algorithm=camp["algorithm_version"],
                              x_part3_evidence_ids=[m["evidence_id"] for _, m in obs_list], **common)
    objs.append(campaign)
    for obs, m in obs_list:
        objs.append(stix2.Relationship(id=_id("relationship", "%s|member|%s" % (m["email_id"], campaign_id)), relationship_type="related-to",
                                       source_ref=obs.id, target_ref=campaign.id, confidence=int(round(m["confidence"] * 100)),
                                       x_part3_evidence_id=m["evidence_id"], x_part3_method=camp["algorithm_version"], **common))
    shared_dom = {k: v for k, v in counts["domain"].items() if len(v) >= 2}
    shared_ip = {k: v for k, v in counts["ip"].items() if len(v) >= 2}
    shared_hash = {k: v for k, v in counts["hash"].items() if len(v) >= 2}
    if shared_dom or shared_ip:
        infra = stix2.Infrastructure(id=_id("infrastructure", campaign_id), name="Shared infrastructure of %s" % campaign_id,
                                     infrastructure_types=["phishing"], first_seen=min(times), last_seen=max(times),
                                     description="Domains and IPs that appear in two or more emails of the campaign. A shared IP may be shared hosting.", **common)
        objs.append(infra)
        objs.append(stix2.Relationship(id=_id("relationship", "uses|" + campaign_id), relationship_type="uses", source_ref=campaign.id, target_ref=infra.id, **common))
        for coll in (shared_dom, shared_ip):
            for val, ids in coll.items():
                objs.append(stix2.Relationship(id=_id("relationship", "consists|%s|%s" % (campaign_id, val)), relationship_type="consists-of",
                                               source_ref=infra.id, target_ref=ids[0], **common))
    n_ind = 0
    if camp["status"] == "confirmed":     # only analyst-confirmed campaigns produce indicators
        pats = [("Landing domain %s" % v, "[domain-name:value = '%s']" % v) for v in shared_dom] + \
               [("Attachment SHA-256 %s..." % h[:12], "[file:hashes.'SHA-256' = '%s']" % h) for h in shared_hash]
        for name, pat in pats:
            ind = stix2.Indicator(id=_id("indicator", campaign_id + pat), name="%s (%s)" % (name, campaign_id), pattern=pat, pattern_type="stix",
                                  valid_from=min(times), indicator_types=["malicious-activity"], confidence=int(round(mean * 100)),
                                  description="Derived from an analyst-confirmed campaign. Verify before using for blocking.", **common)
            objs += [ind, stix2.Relationship(id=_id("relationship", "indicates|" + ind.id), relationship_type="indicates",
                                             source_ref=ind.id, target_ref=campaign.id, **common)]
            n_ind += 1
    return stix2.Bundle(id=_id("bundle", campaign_id + now), objects=objs, allow_custom=True), n_ind, [m["email_id"] for _, m in obs_list]

def export(conn, campaign_id, out_path, record_export=True):
    bundle, n_ind, email_ids = build_bundle(conn, campaign_id)
    text = bundle.serialize(pretty=True)
    with open(out_path, "w", encoding="utf-8") as f: f.write(text)
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if record_export:
        for e in email_ids:
            ev = "E-" + e[4:]
            ledger.append(conn, ev, "EXPORTED", "part3.stix", {"file": out_path.split("/")[-1], "sha256": sha, "format": "stix2.1", "campaign": campaign_id})
        conn.commit()
    return {"path": out_path, "sha256": sha, "objects": len(bundle.objects), "indicators": n_ind, "text": text}
