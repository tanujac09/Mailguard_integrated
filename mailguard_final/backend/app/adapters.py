"""
adapters.py — translates a mailguard_final pipeline result into the
Part 3 "bundle" contract defined in part3_starter/sample_bundle.json.

This file is purely ADDITIVE. It does not import, modify, or touch
mailguard_final's pipeline.py, any module in modules/ (including
nlp_engine.py / content_module.py's ML scoring), or part3_starter's
own code in any way. It only reads the dicts those files already
produce and re-shapes them.

Drop this into mailguard_final/backend/app/adapters.py.
See INTEGRATION.md for the one line you'd add to routers/emails.py
to actually call this — nothing is wired in automatically.
"""
import re
from datetime import datetime, timezone
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlparse


def _step_by_key(steps: list, key: str):
    return next((s for s in steps if s["step_key"] == key), None)


def _to_utc_iso(date_header) -> str:
    """
    RFC 2822 'Date' header -> 'YYYY-MM-DDTHH:MM:SSZ' (what part3 requires).
    Falls back to current UTC time if the header is missing/unparseable
    (synthetic/demo .eml files sometimes have malformed dates).
    """
    try:
        dt = parsedate_to_datetime(date_header)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    except Exception:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_body(text_body: str, html_body: str) -> str:
    """Light normalization: strip HTML tags if no plain-text part, collapse whitespace."""
    raw = text_body or ""
    if not raw and html_body:
        raw = re.sub(r"<[^>]+>", " ", html_body)
    raw = re.sub(r"\s+", " ", raw).strip()
    return raw


def _parse_asn(asn_field):
    """
    origin_module (via ip-api.com) returns asn as a string like
    'AS15169 Google LLC'. part3 wants a bare int ASN + org string.
    Returns (None, None) if asn_field is missing/unparseable.
    """
    if not asn_field:
        return None, None
    m = re.match(r"AS(\d+)\s*(.*)", str(asn_field))
    if not m:
        return None, str(asn_field) or None
    number = int(m.group(1))
    org = m.group(2).strip() or None
    return number, org


def build_bundle(parsed, steps: list, fusion: dict, filename: str, raw_bytes: bytes) -> dict:
    """
    parsed:    the ParsedEmail returned by email_parser.parse_eml (unchanged)
    steps:     result["steps"] from pipeline.run_pipeline (unchanged)
    fusion:    result["fusion"] from pipeline.run_pipeline (unchanged)
    filename:  original uploaded filename
    raw_bytes: the raw .eml bytes

    Returns a dict matching part3_starter/sample_bundle.json exactly.

    ── Judgment call flagged for your review (see INTEGRATION.md) ──
    mailguard's auth_module checks whether SPF/DMARC records are
    *published* for the domain and whether a DKIM header is merely
    *present* — not a true per-message pass/fail/align verification.
    The mapping below is the most defensible reading of that, not a
    verified equivalence. Worth a line in your report as a stated
    limitation rather than something to silently paper over.
    """
    auth = _step_by_key(steps, "auth")
    origin = _step_by_key(steps, "origin")
    link = _step_by_key(steps, "links")

    auth_details = auth["details"] if auth else {}
    origin_details = origin["details"] if origin else {}
    link_details = link["details"] if link else {"links": [], "attachments": []}

    _, from_addr = parseaddr(parsed.from_header or "")
    from_addr = (from_addr or "").lower()

    asn_number, asn_org = _parse_asn(origin_details.get("asn"))

    urls = []
    for l in link_details.get("links", []):
        final = l.get("final_destination") or l["href"]
        try:
            final_domain = urlparse(final).hostname
        except Exception:
            final_domain = None
        urls.append({
            "url": l["href"],
            "final_url": final,
            "final_domain": final_domain,
        })

    attachments = [
        {"filename": a["filename"], "sha256": a["sha256"]}
        for a in link_details.get("attachments", [])
    ]

    spf = "pass" if auth_details.get("spf_record_found") else "fail"
    dmarc = "pass" if auth_details.get("dmarc_record_found") else "fail"
    dkim = "pass" if auth_details.get("has_dkim_signature") else "none"

    return {
        "bundle_version": "0.1",
        "artifact": {
            "filename": filename,
            "sha256": parsed.sha256,
            "size_bytes": len(raw_bytes),
            "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": "mailguard_final",
        },
        "email": {
            "message_id": parsed.message_id,
            "received_at": _to_utc_iso(parsed.date_header),
            "subject": parsed.subject,
            "from_addr": from_addr,
            "body_norm": _clean_body(parsed.body_text, parsed.body_html),
        },
        "part1": {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "trust_boundary_ip": origin_details.get("ip"),
        },
        "part2": {
            "asn": asn_number,
            "asn_org": asn_org,
            "urls": urls,
            "attachments": attachments,
            "risk_score": round((fusion.get("fraud_score") or 0) / 100, 3),
        },
    }
