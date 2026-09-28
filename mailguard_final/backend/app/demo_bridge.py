"""
demo_bridge.py — exercises adapters.py + summarizer.py end to end
against one sample .eml, with NO FastAPI app, NO database, and NO
changes to any mailguard_final file. Good for testing the bundle
mapping and PII masking before wiring anything into the real app.

Run from mailguard_final/backend/, after copying adapters.py,
bridge.py and summarizer.py into backend/app/:

    python -m app.demo_bridge sample_emails/phishing_sample1.eml

Requires GEMINI_API_KEY in your environment/.env for the summarizer
part; the bundle-building part works without it.
"""
import json
import sys

from .email_parser import parse_eml
from .pipeline import run_pipeline
from . import build_bundle
from .summarizer import mask_pii, summarize_with_gemini


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m app.demo_bridge <path-to-eml>")
        sys.exit(1)

    path = sys.argv[1]
    with open(path, "rb") as f:
        raw_bytes = f.read()
    filename = path.split("/")[-1]

    # --- run mailguard's existing pipeline, unchanged ---
    result = run_pipeline(raw_bytes, filename)

    print("=" * 70)
    print("FRAUD SCORE (from mailguard's existing fusion.py):", result["fusion"]["fraud_score"],
          "-", result["fusion"]["verdict"])

    # --- build the part3 bundle ---
    bundle = build_bundle(result["parsed"], result["steps"], result["fusion"], filename, raw_bytes)
    print("=" * 70)
    print("PART 3 BUNDLE:")
    print(json.dumps(bundle, indent=2))

    # --- PII masking demo, independent of Gemini ---
    body = bundle["email"]["body_norm"]
    masked, mapping = mask_pii(body)
    print("=" * 70)
    print("ORIGINAL BODY (first 300 chars):", body[:300])
    print("-" * 70)
    print("MASKED BODY (first 300 chars):", masked[:300])
    print("-" * 70)
    print("ENTITIES MASKED:", mapping)

    # --- Gemini summary (only runs if GEMINI_API_KEY is set) ---
    print("=" * 70)
    summary = summarize_with_gemini(body)
    print("GEMINI SUMMARY RESULT:", json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
