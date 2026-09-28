"""Forensic dossier (PDF) for one email and its campaign, generated only from stored data."""
import hashlib, json
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, Preformatted
from . import explain, ledger, actions

NAVY, TEAL, GREY, LIGHT = colors.HexColor("#12284C"), colors.HexColor("#0E7C86"), colors.HexColor("#5F6B7A"), colors.HexColor("#F3F5F8")
B = ParagraphStyle("b", fontName="Helvetica", fontSize=9, leading=12, spaceAfter=4)
SM = ParagraphStyle("sm", parent=B, fontSize=7.8, leading=10, spaceAfter=0)
SMB = ParagraphStyle("smb", parent=SM, fontName="Helvetica-Bold", textColor=colors.white)
H1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=NAVY, spaceBefore=12, spaceAfter=4)
TITLE = ParagraphStyle("t", fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=NAVY)
CODE = ParagraphStyle("c", fontName="Courier", fontSize=7.2, leading=9, backColor=LIGHT, borderPadding=4, spaceAfter=6)

def _tbl(rows, widths, header=True):
    data = [[Paragraph(str(c), SMB if (header and i == 0) else SM) for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=[w * 17 * cm / sum(widths) for w in widths], repeatRows=1 if header else 0)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#C9D1DB")),
          ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header: st.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    else: st.append(("BACKGROUND", (0, 0), (0, -1), LIGHT))
    t.setStyle(TableStyle(st)); return [t, Spacer(1, 6)]

def _ev(email_id): return "E-" + email_id[4:]

def build_findings(conn, email_id, b, camp, summ, links):
    p1, p2 = b["part1"], b["part2"]; ev = _ev(email_id); F = []
    F.append(("observation", "Authentication results: SPF=%s, DKIM=%s, DMARC=%s." % (p1.get("spf"), p1.get("dkim"), p1.get("dmarc")), [ev], "Part 1 (email headers, DNS)", None))
    if p1.get("trust_boundary_ip"):
        F.append(("observation", "Earliest trusted originating IP is %s (AS%s, %s)." % (p1["trust_boundary_ip"], p2.get("asn"), p2.get("asn_org")), [ev], "Part 1 relay analysis, Part 2 enrichment", None))
    if p1.get("lookalike_of"):
        F.append(("observation", "Sender domain is flagged as a lookalike of %s." % p1["lookalike_of"], [ev], "Part 1 homoglyph/edit-distance check", None))
    if camp:
        others = [l["other"] for l in links]
        for kind, label in (("domain", "landing domain"), ("hash", "attachment hash")):
            for v, n in summ["shared"][kind][:1]:
                if n > 1:
                    F.append(("correlation", "The %s %s appears in %d emails of campaign %s." % (label, v, n, camp["campaign_id"]), [_ev(o) for o in others[:5]] or [ev], "Part 3 graph correlation", None))
        F.append(("assessment", "This email is likely associated with campaign %s (algorithmic membership confidence %.2f; %s)." % (camp["campaign_id"], camp["confidence"], {"confirmed": "analyst-reviewed: CONFIRMED", "rejected": "analyst-reviewed: REJECTED"}.get(camp["status"], "not analyst-reviewed")),
                  [ev] + [_ev(o) for o in others[:4]], "Part 3 correlation and clustering (%s)" % camp["algorithm_version"], camp["confidence"]))
    return F

def generate(conn, email_id, out_path, case_id=None, record_export=True):
    e = conn.execute("SELECT * FROM emails WHERE email_id=?", (email_id,)).fetchone()
    b = json.loads(e["raw_bundle"]); p1, p2 = b["part1"], b["part2"]
    art = conn.execute("SELECT * FROM artifacts WHERE artifact_id=?", (e["artifact_id"],)).fetchone()
    evid = art["evidence_id"]; case_id = case_id or "CASE-" + email_id[4:10].upper()
    camp = conn.execute("SELECT m.campaign_id, m.confidence, c.size, c.notes, c.algorithm_version, c.status FROM campaign_members m JOIN campaigns c USING (campaign_id) WHERE m.email_id=?", (email_id,)).fetchone()
    summ = explain.campaign_summary(conn, camp["campaign_id"]) if camp else None
    links = []
    for r in conn.execute("SELECT from_id, to_id, confidence, strength, details FROM relationships WHERE type='LINKED_TO' AND (from_id=? OR to_id=?) ORDER BY confidence DESC LIMIT 5", (email_id, email_id)):
        links.append({"other": r["to_id"] if r["from_id"] == email_id else r["from_id"], "score": r["confidence"], "strength": r["strength"], "d": json.loads(r["details"])})
    near = conn.execute("SELECT from_id, to_id, confidence, details FROM relationships WHERE type='CANDIDATE_REJECTED' AND (from_id=? OR to_id=?) ORDER BY confidence DESC LIMIT 3", (email_id, email_id)).fetchall()
    custody = conn.execute("SELECT seq, type, actor, ts, prev_hash, event_hash FROM custody_events WHERE evidence_id=? ORDER BY seq", (evid,)).fetchall()
    ok, bad = ledger.verify(conn, evid)
    risk = p2.get("risk_score"); sev = "not provided" if risk is None else ("High" if risk >= 0.8 else "Medium" if risk >= 0.5 else "Low")
    S = []
    S += [Paragraph("Forensic Dossier", TITLE), Paragraph("Email investigation report (DRAFT: analyst review required)", ParagraphStyle("x", parent=B, textColor=GREY)), Spacer(1, 8)]
    S += [Paragraph("1. Case summary", H1)]
    S += _tbl([["Case ID", case_id], ["Incident type", "Suspected fraudulent email"], ["Severity (from Part 2 risk score %s)" % risk, sev],
               ["Campaign", ("%s (%d emails), membership confidence %.2f" % (camp["campaign_id"], camp["size"], camp["confidence"])) if camp else "No campaign association"],
               ["Review status", {"confirmed": "Campaign confirmed by analyst", "rejected": "Campaign rejected by analyst"}.get(camp["status"] if camp else None, "Automated draft, not yet analyst-reviewed")],
               ["Email received", e["received_at"]], ["Report generated", ledger.now_iso()]], [3, 9], header=False)
    if camp and camp["notes"]: S.append(Paragraph("<b>Review note:</b> " + camp["notes"], B))
    S.append(Paragraph("Confidence values are algorithmic assessments, not legal proof. This report supports an investigation; it does not identify any person.", B))
    S += [Paragraph("2. Evidence identity", H1)]
    S += _tbl([["Evidence ID", evid], ["Artifact ID / file", "%s / %s" % (art["artifact_id"], art["filename"])], ["SHA-256", art["sha256"]],
               ["Size", "%s bytes" % art["size_bytes"]], ["Collected", "%s (source: %s)" % (art["collected_at"], art["source"])],
               ["Custody chain check", "INTACT" if ok else "BROKEN at event %s" % bad]], [3, 9], header=False)
    S += [Paragraph("3. Header and relay reconstruction", H1)]
    S += _tbl([["Item", "Value", "Source"], ["Earliest trusted external IP", p1.get("trust_boundary_ip") or "not available", "Part 1"],
               ["ASN / organisation", "AS%s / %s" % (p2.get("asn"), p2.get("asn_org")), "Part 2"]], [3, 5, 2])
    S.append(Paragraph("The per-hop Received table is not part of bundle v0.1; add it to the Part 1 hand-off to show the full path here.", SM))
    S += [Paragraph("4. Authentication findings", H1)]
    S += _tbl([["Check", "Result"], ["SPF", p1.get("spf")], ["DKIM", p1.get("dkim")], ["DMARC", p1.get("dmarc")],
               ["Sender address", e["from_addr"]], ["Lookalike of", p1.get("lookalike_of") or "none flagged"]], [3, 6])
    S += [Paragraph("5. Infrastructure correlation", H1)]
    rows = [["Indicator", "Value", "Emails in this campaign"]]
    if summ:
        for kind, label in (("ip", "Originating IP"), ("domain", "Landing domain"), ("hash", "Attachment hash")):
            for v, n in summ["shared"][kind]: rows.append([label, v, n])
    else:
        rows += [["Originating IP", p1.get("trust_boundary_ip"), "-"]]
    S += _tbl(rows, [3, 6, 2])
    S.append(Paragraph("A shared IP alone is not treated as proof of a shared campaign (shared hosting can put unrelated sites on one address).", SM))
    S += [Paragraph("6. Campaign correlation", H1)]
    if links:
        for l in links[:3]:
            d = l["d"]; sig = "; ".join("%s %.2f" % (k, v["value"]) for k, v in sorted(d["signals"].items(), key=lambda kv: -kv[1]["contribution"]) if v["value"] > 0)
            S.append(Paragraph("<b>Linked to %s</b> - score %.2f (%s). Exact matches: %s. Signals: %s." % (l["other"], l["score"], d["reason"], ", ".join(d["hard_signals"]) or "none", sig), B))
    else:
        S.append(Paragraph("No links to other emails were recorded.", B))
    for r in near:
        d = json.loads(r["details"]); other = r["to_id"] if r["from_id"] == email_id else r["from_id"]
        S.append(Paragraph("<b>Not linked to %s</b> - score %.2f (%s)." % (other, r["confidence"], d["reason"]), SM))
    S += [Paragraph("7. Evidence trail (findings)", H1)]
    F = build_findings(conn, email_id, b, camp, summ, links)
    S += _tbl([["ID", "Type", "Finding", "Supported by", "Source", "Conf."]] +
              [["F-%02d" % (i + 1), t, s, ", ".join(dict.fromkeys(ev)), src, "-" if c is None else "%.2f" % c] for i, (t, s, ev, src, c) in enumerate(F)], [1, 1.6, 5, 2.6, 3, 1])
    S.append(Paragraph("Types: observation = read from the evidence; correlation = computed similarity or shared indicator; assessment = algorithmic judgement, revisable.", SM))
    S += [Paragraph("8. Timeline", H1)]
    tl = explain.timeline(conn, camp["campaign_id"]) if camp else []
    if not tl:
        tl = [{"time": e["received_at"], "kind": "EMAIL", "item": email_id, "what": "received from " + e["from_addr"]}] + \
             [{"time": c["ts"], "kind": "CUSTODY", "item": evid, "what": "%s by %s" % (c["type"], c["actor"])} for c in custody]
    tl = [t for t in tl if t["kind"] == "EMAIL" or t["item"] == evid]
    S += _tbl([["Time (UTC)", "Kind", "Item", "Event"]] + [[t["time"], t["kind"], t["item"], t["what"]] for t in tl], [3, 1.5, 3, 6])
    S += [Paragraph("9. Analyst actions", H1)]
    acts = actions.for_email(conn, email_id)
    if not acts:
        S.append(Paragraph("No analyst actions recorded.", B))
    else:
        def tgt(x): return x["target_id"] + (" <-> " + x["target_id2"] if x["target_id2"] else "")
        S += _tbl([["Time (UTC)", "Analyst", "Action", "Target", "Comment"]] + [[x["ts"], x["analyst"], x["action"], tgt(x), x["comment"]] for x in acts], [2.6, 2, 2.2, 4.2, 5])
    S += [Paragraph("10. Limitations and caveats", H1)]
    lim = ["IP geolocation and ownership are approximate; an IP owner is not the person who sent the email.",
           "Shared infrastructure can create false links; threat-intelligence data can be stale.",
           "Header data may be missing or forged. Clustering is probabilistic and campaign membership is not attribution.",
           "Scoring weights are placeholders tuned on demo data and must be re-tuned on real data.",
           "The custody chain is tamper-evident, not tamper-proof. This report does not by itself establish legal admissibility."]
    if camp and camp["notes"]: lim.append("Case-specific: " + camp["notes"])
    S += [Paragraph("- " + x, B) for x in lim]
    S += [Paragraph("Appendix A. Custody ledger", H1)]
    S += _tbl([["#", "Event", "Actor", "Time", "Event hash (first 16)"]] + [[c["seq"], c["type"], c["actor"], c["ts"], c["event_hash"][:16]] for c in custody], [0.6, 2, 2.5, 3, 4])
    S += [Paragraph("Appendix B. Draft electronic-evidence certificate fields (for human and legal review)", H1)]
    S += _tbl([["Field", "Pre-filled by system"], ["Description of record", "Email file %s (message/rfc822), %s bytes" % (art["filename"], art["size_bytes"])],
               ["Hash function and value", "SHA-256: " + art["sha256"]], ["Collected", art["collected_at"]],
               ["Device / source details", "To be completed by the person in charge"], ["Expert declaration", "To be completed and signed by a qualified expert"],
               ["Names, signatures, date, place", "To be completed by signatories"]], [3, 8])
    S.append(Paragraph("This is not a certificate under any law. Requirements (for example Bharatiya Sakshya Adhiniyam 2023, section 63 and its Schedule) must be confirmed by a lawyer.", SM))
    S += [Paragraph("Appendix C. Methodology", H1),
          Paragraph("Bundle v%s from Parts 1 and 2; correlation %s (weights: infra, url, content, attachment, identity, time; threshold on synthetic data); clustering by connected components checked with Louvain. This report is generated only from stored records. Its own SHA-256 is recorded in the custody ledger as an EXPORTED event after generation." % (b.get("bundle_version"), "corr-0.1"), B)]
    def deco(c, d):
        c.saveState(); c.setFont("Helvetica", 7.5); c.setFillColor(GREY)
        c.drawString(2 * cm, A4[1] - 1.3 * cm, "Forensic Dossier | %s | DRAFT, analyst review required" % case_id)
        c.drawString(2 * cm, 1.0 * cm, "Evidence %s | SHA-256 %s..." % (evid, art["sha256"][:16])); c.drawRightString(A4[0] - 2 * cm, 1.0 * cm, "Page %d" % d.page); c.restoreState()
    SimpleDocTemplate(out_path, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.9 * cm, bottomMargin=1.7 * cm, title="Forensic Dossier " + case_id).build(S, onFirstPage=deco, onLaterPages=deco)
    sha = hashlib.sha256(open(out_path, "rb").read()).hexdigest()
    if record_export:
        ledger.append(conn, evid, "EXPORTED", "part3.dossier", {"file": out_path.split("/")[-1], "sha256": sha, "format": "pdf"}); conn.commit()
    return {"path": out_path, "sha256": sha, "case_id": case_id}
