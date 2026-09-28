"""
Part 2 style module: Link & Attachment Sandbox (lightweight, HTTP-only
version - no headless browser, safe to run anywhere with no network
egress concerns beyond outbound HTTPS).

What it does:
  - For each link, compares the visible anchor text to the real href
    (a classic phishing trick: text says "your-bank.com", href points
    elsewhere).
  - Follows redirects (HTTP-only, so JS-based redirects are NOT
    resolved - documented limitation, see the design doc).
  - Runs a cheap edit-distance check against a small trusted-domain list
    to catch typosquats / homoglyphs.
  - Hashes every attachment (SHA-256) and checks it against a local
    blocklist file, plus VirusTotal if VIRUSTOTAL_API_KEY is set.
"""
import os
import re
import httpx
from urllib.parse import urlparse

from ..config import settings

TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "paypal.com", "apple.com", "amazon.com",
    "bankofindia.co.in", "sbi.co.in", "icicibank.com", "hdfcbank.com",
]

BLOCKLIST_PATH = os.path.join(os.path.dirname(__file__), "local_hash_blocklist.txt")


def _load_blocklist() -> set:
    if not os.path.exists(BLOCKLIST_PATH):
        return set()
    with open(BLOCKLIST_PATH) as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def _check_lookalike(domain: str) -> str:
    if not domain:
        return None
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted:
            return None
        dist = _levenshtein(domain, trusted)
        if 0 < dist <= 2:
            return trusted
    return None


def _follow_redirect(url: str) -> dict:
    try:
        r = httpx.get(url, follow_redirects=True, timeout=6.0)
        return {"final_url": str(r.url), "status_code": r.status_code, "error": None}
    except Exception as exc:
        return {"final_url": None, "status_code": None, "error": str(exc)}


def _vt_lookup(sha256: str) -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"checked": False}
    try:
        r = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            timeout=10.0,
        )
        if r.status_code == 404:
            return {"checked": True, "known": False}
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        return {"checked": True, "known": True, "malicious_engines": malicious, "stats": stats}
    except Exception as exc:
        return {"checked": True, "error": str(exc)}


def analyze_links_and_attachments(parsed_email, follow_links: bool = True, max_links: int = 5) -> dict:
    blocklist = _load_blocklist()

    link_findings = []
    mismatch_count = 0
    lookalike_count = 0

    for link in parsed_email.links[:max_links]:
        href = link["href"]
        anchor = link.get("anchor_text", "")
        domain = _domain_of(href)

        anchor_domain = _domain_of(anchor) if anchor.startswith("http") else None
        mismatch = bool(anchor_domain and anchor_domain != domain)
        lookalike_target = _check_lookalike(domain)

        redirect_info = _follow_redirect(href) if follow_links else {"final_url": None, "status_code": None, "error": "skipped"}

        if mismatch:
            mismatch_count += 1
        if lookalike_target:
            lookalike_count += 1

        link_findings.append({
            "href": href,
            "anchor_text": anchor,
            "domain": domain,
            "anchor_vs_href_mismatch": mismatch,
            "lookalike_of": lookalike_target,
            "final_destination": redirect_info.get("final_url"),
            "http_status": redirect_info.get("status_code"),
            "fetch_error": redirect_info.get("error"),
        })

    attachment_findings = []
    malicious_attachment = False
    for att in parsed_email.attachments:
        blocklisted = att.sha256.lower() in blocklist
        vt = _vt_lookup(att.sha256)
        is_malicious = blocklisted or (vt.get("malicious_engines", 0) or 0) > 0
        if is_malicious:
            malicious_attachment = True
        attachment_findings.append({
            "filename": att.filename,
            "content_type": att.content_type,
            "size": att.size,
            "sha256": att.sha256,
            "on_local_blocklist": blocklisted,
            "virustotal": vt,
            "flagged_malicious": is_malicious,
        })

    status = "green"
    findings = []

    if malicious_attachment:
        status = "red"
        findings.append("At least one attachment matched a known-malicious hash.")
    if lookalike_count:
        status = "red"
        findings.append(f"{lookalike_count} link(s) point to a lookalike/typosquat of a trusted domain.")
    if mismatch_count and status != "red":
        status = "amber"
        findings.append(f"{mismatch_count} link(s) have anchor text that doesn't match the real destination.")

    if not findings:
        findings.append("No suspicious links or attachments detected.")

    score = 0
    if malicious_attachment:
        score = 100
    elif lookalike_count:
        score = 80
    elif mismatch_count:
        score = 35

    return {
        "step_key": "links",
        "title": "Link & Attachment Sandbox",
        "status": status,
        "summary": findings[0],
        "details": {
            "links_checked": len(link_findings),
            "links": link_findings,
            "attachments_checked": len(attachment_findings),
            "attachments": attachment_findings,
            "findings": findings,
            "manual_steps_this_replaces": [
                "Hover every link and compare shown text vs real URL",
                "Follow redirect chains in an isolated browser/VM",
                "Hash every attachment and check it against threat-intel feeds",
            ],
        },
        "score": score,
    }
