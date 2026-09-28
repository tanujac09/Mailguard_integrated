"""
Orchestrates the full analysis pipeline and builds the ordered list of
"analyst flowchart" steps: what a human would check manually, step by
step, if this tool did not exist. Each step is green (no problem found),
amber (needs a human look), or red (a concrete problem was detected).
Clicking a step in the UI shows its `details` payload.
"""
from .email_parser import parse_eml
from .modules.auth_module import analyze_auth
from .modules.origin_module import analyze_origin
from .modules.content_module import analyze_content
from .modules.link_module import analyze_links_and_attachments
from .modules.fusion import fuse


def _ingestion_step(parsed_email) -> dict:
    return {
        "step_key": "ingestion",
        "title": "Ingestion & Integrity Hashing",
        "status": "green",
        "summary": f"Email parsed successfully, SHA-256 computed for chain-of-custody.",
        "details": {
            "sha256": parsed_email.sha256,
            "subject": parsed_email.subject,
            "from": parsed_email.from_header,
            "date": parsed_email.date_header,
            "attachments_found": len(parsed_email.attachments),
            "links_found": len(parsed_email.links),
            "manual_steps_this_replaces": [
                "Save the raw .eml file untouched, before any analysis",
                "Compute and record a SHA-256 hash for chain-of-custody",
            ],
        },
        "score": 0,
    }


def run_pipeline(raw_bytes: bytes, filename: str) -> dict:
    parsed = parse_eml(raw_bytes, filename)

    ingestion = _ingestion_step(parsed)
    auth_result = analyze_auth(parsed)
    origin_result = analyze_origin(parsed)
    content_result = analyze_content(parsed)
    link_result = analyze_links_and_attachments(parsed)

    step_results = {
        "auth": auth_result,
        "origin": origin_result,
        "content": content_result,
        "links": link_result,
    }
    fusion_result = fuse(step_results)

    ordered_steps = [ingestion, auth_result, origin_result, content_result, link_result]
    for idx, step in enumerate(ordered_steps):
        step["order_index"] = idx

    return {
        "parsed": parsed,
        "steps": ordered_steps,
        "fusion": fusion_result,
    }
