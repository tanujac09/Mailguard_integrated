"""
Part 2 style module: Composite Fraud Risk Scoring.

fraud_score = w1*auth + w2*origin + w3*content + w4*links
A hard-fail condition (DMARC reject + failed alignment, or a malicious
attachment) overrides the weighted sum to the maximum score - a single
strong signal should not get diluted by three clean ones.
"""
from ..config import settings

WEIGHTS = {
    "auth": 0.35,
    "origin": 0.20,
    "content": 0.25,
    "links": 0.20,
}


def fuse(step_results: dict) -> dict:
    weighted = sum(WEIGHTS[k] * step_results[k]["score"] for k in WEIGHTS)
    weighted = round(min(weighted, 100), 1)

    hard_fail = (
        step_results["auth"]["details"].get("hard_fail_spoof")
        or any(a.get("flagged_malicious") for a in step_results["links"]["details"].get("attachments", []))
    )

    final_score = 100.0 if hard_fail else weighted

    if final_score >= settings.FRAUD_THRESHOLD:
        verdict = "Fraudulent"
    elif final_score >= settings.FLAG_THRESHOLD:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    flagged = 1 if final_score >= settings.FLAG_THRESHOLD else 0

    return {
        "fraud_score": final_score,
        "verdict": verdict,
        "flagged": flagged,
        "hard_fail_triggered": bool(hard_fail),
        "weights_used": WEIGHTS,
    }
