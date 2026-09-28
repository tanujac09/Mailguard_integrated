"""
summarizer.py — mask PII, then summarize the MASKED text with Gemini.

Completely standalone. Does not import, modify, or call anything in
nlp_engine.py, content_module.py, or any other ML/NLP scoring code —
fraud/risk scores are computed exactly as before; this only adds an
optional plain-English summary for the analyst UI.

Real PII (emails, phone numbers, IPs, card-like numbers, URLs) is
replaced with stable placeholder tokens BEFORE anything is sent to
Gemini. The token -> original-value mapping never leaves this
process. Placeholders are restored locally afterward if you want the
analyst to see real values in the final summary.
"""
import os
import re
from typing import Tuple, Dict

import httpx

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# Order matters: more specific patterns first, so e.g. a URL's digits
# don't get re-caught by the phone-number pattern afterward.
PII_PATTERNS = [
    ("EMAIL", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("URL", re.compile(r"https?://[^\s<>\")]+")),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("PHONE", re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b")),
]


def mask_pii(text: str) -> Tuple[str, Dict[str, str]]:
    """
    Replace PII in `text` with stable placeholders like [EMAIL_1].
    The SAME original value always maps to the SAME placeholder
    within one call, so a summary that repeats an address still
    reads coherently.

    Returns (masked_text, mapping) where mapping is
    {placeholder: original_value}. Keep `mapping` local — never send
    it anywhere.
    """
    mapping: Dict[str, str] = {}
    value_to_placeholder: Dict[str, str] = {}
    counters: Dict[str, int] = {}
    masked = text

    for label, pattern in PII_PATTERNS:
        def _replace(match, label=label):
            original = match.group(0)
            if original in value_to_placeholder:
                return value_to_placeholder[original]
            counters[label] = counters.get(label, 0) + 1
            placeholder = f"[{label}_{counters[label]}]"
            value_to_placeholder[original] = placeholder
            mapping[placeholder] = original
            return placeholder

        masked = pattern.sub(_replace, masked)

    return masked, mapping


def unmask(text: str, mapping: Dict[str, str]) -> str:
    """Swap placeholders back to real values. Local use only — never re-send this."""
    for placeholder, original in mapping.items():
        text = text.replace(placeholder, original)
    return text


def summarize_with_gemini(text: str, max_chars: int = 4000) -> dict:
    """
    Masks PII in `text`, sends ONLY the masked version to Gemini for a
    short summary, then restores real values locally for display.

    Returns:
      {"summary": <str, PII restored>,
       "summary_masked": <str, exactly what came back from Gemini>,
       "pii_entities_masked": <int>}
      or {"summary": None, "error": <str>} if the call fails / no key set.
    """
    if not GEMINI_API_KEY:
        return {"summary": None, "error": "GEMINI_API_KEY not set"}

    masked_text, mapping = mask_pii(text[:max_chars])

    prompt = (
        "Summarize the following email content in 2-3 plain-English "
        "sentences for a fraud analyst. The text contains placeholder "
        "tokens such as [EMAIL_1] or [PHONE_1] standing in for real "
        "personal data. Keep every placeholder exactly as written in "
        "your summary — do not guess, invent, or omit what it might be.\n\n"
        f"{masked_text}"
    )

    try:
        r = httpx.post(
            GEMINI_URL,
            params={"key": GEMINI_API_KEY},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=15.0,
        )
        r.raise_for_status()
        data = r.json()
        masked_summary = data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as exc:
        return {"summary": None, "error": str(exc)}

    return {
        "summary": unmask(masked_summary, mapping),
        "summary_masked": masked_summary,
        "pii_entities_masked": len(mapping),
    }
