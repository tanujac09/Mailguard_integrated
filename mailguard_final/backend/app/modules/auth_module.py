"""
Part 1 style module: header authenticity.

What a human analyst does manually:
  1. Look up whether the sending domain publishes SPF / DMARC records.
  2. Check whether the message carries a DKIM-Signature at all.
  3. Compare the visible From: address against Return-Path and Reply-To
     to catch "envelope vs header" mismatches used in spoofing.
  4. If DMARC policy is p=reject and alignment fails -> this is about as
     close to a definitive spoof as header analysis gets.

This module keeps the check offline-safe: if DNS lookups fail (e.g. no
network in a sandboxed environment) it degrades gracefully to "unknown"
instead of crashing the whole pipeline.
"""
import re
from typing import Optional

try:
    import checkdmarc
except Exception:  # pragma: no cover
    checkdmarc = None


def _domain_dmarc_spf(domain: str) -> dict:
    """Best-effort DNS lookup. Never raises."""
    result = {
        "spf_record_found": None,
        "dmarc_record_found": None,
        "dmarc_policy": None,
        "lookup_error": None,
    }
    if not checkdmarc or not domain:
        result["lookup_error"] = "DNS lookup library unavailable or empty domain"
        return result
    try:
        report = checkdmarc.check_domains([domain], parked=False)
        spf = report.get("spf", {})
        dmarc = report.get("dmarc", {})
        result["spf_record_found"] = bool(spf.get("record"))
        result["dmarc_record_found"] = bool(dmarc.get("record"))
        tags = dmarc.get("tags", {}) if isinstance(dmarc, dict) else {}
        policy = tags.get("p", {}).get("value") if isinstance(tags.get("p"), dict) else None
        result["dmarc_policy"] = policy
    except Exception as exc:  # network down, domain doesn't resolve, etc.
        result["lookup_error"] = str(exc)
    return result


def analyze_auth(parsed_email) -> dict:
    from_domain = parsed_email.from_domain
    return_path_domain = None
    reply_to_domain = None

    if parsed_email.return_path:
        m = re.search(r"@([A-Za-z0-9.-]+)", parsed_email.return_path)
        return_path_domain = m.group(1).lower() if m else None
    if parsed_email.reply_to:
        m = re.search(r"@([A-Za-z0-9.-]+)", parsed_email.reply_to)
        reply_to_domain = m.group(1).lower() if m else None

    has_dkim_signature = "DKIM-Signature" in parsed_email.raw_header_block

    dns_info = _domain_dmarc_spf(from_domain) if from_domain else {
        "spf_record_found": None, "dmarc_record_found": None,
        "dmarc_policy": None, "lookup_error": "No From domain parsed",
    }

    return_path_mismatch = bool(
        return_path_domain and from_domain and return_path_domain != from_domain
    )
    reply_to_mismatch = bool(
        reply_to_domain and from_domain and reply_to_domain != from_domain
    )

    hard_fail = bool(
        dns_info.get("dmarc_policy") == "reject" and return_path_mismatch
    )

    findings = []
    status = "green"

    if dns_info.get("lookup_error"):
        findings.append(f"DNS lookup incomplete: {dns_info['lookup_error']}")
        status = "amber"
    else:
        if not dns_info.get("spf_record_found"):
            findings.append(f"Domain '{from_domain}' has no SPF record published.")
            status = "amber"
        if not dns_info.get("dmarc_record_found"):
            findings.append(f"Domain '{from_domain}' has no DMARC record published.")
            status = "amber"

    if not has_dkim_signature:
        findings.append("No DKIM-Signature header present on this message.")
        status = "amber"

    if return_path_mismatch:
        findings.append(
            f"Return-Path domain '{return_path_domain}' does NOT match the "
            f"visible From domain '{from_domain}' - classic envelope spoof pattern."
        )
        status = "red"

    if reply_to_mismatch:
        findings.append(
            f"Reply-To domain '{reply_to_domain}' differs from the visible From "
            f"domain '{from_domain}' - replies would go somewhere the sender didn't show you."
        )
        if status != "red":
            status = "amber"

    if hard_fail:
        findings.append(
            f"HARD FAIL: '{from_domain}' publishes a DMARC p=reject policy, and "
            f"this message fails alignment. This is a strong spoofing indicator."
        )
        status = "red"

    if not findings:
        findings.append(
            f"SPF and DMARC are published for '{from_domain}', DKIM signature is "
            f"present, and From/Return-Path/Reply-To domains are aligned."
        )

    return {
        "step_key": "auth",
        "title": "Header Authentication (SPF / DKIM / DMARC)",
        "status": status,
        "summary": findings[0] if findings else "No authentication issues found.",
        "details": {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "reply_to_domain": reply_to_domain,
            "has_dkim_signature": has_dkim_signature,
            "spf_record_found": dns_info.get("spf_record_found"),
            "dmarc_record_found": dns_info.get("dmarc_record_found"),
            "dmarc_policy": dns_info.get("dmarc_policy"),
            "return_path_mismatch": return_path_mismatch,
            "reply_to_mismatch": reply_to_mismatch,
            "hard_fail_spoof": hard_fail,
            "findings": findings,
            "manual_steps_this_replaces": [
                "Run `dig TXT <domain>` and look for a v=spf1 record",
                "Run `dig TXT _dmarc.<domain>` and read the p= policy tag",
                "Eyeball the From / Return-Path / Reply-To headers side by side",
            ],
        },
        "score": 90 if hard_fail else (55 if status == "red" else (25 if status == "amber" else 0)),
    }
