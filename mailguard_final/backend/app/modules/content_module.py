"""
Part 2 style module: NLP Semantics & Social Engineering Analysis.

Detection layers, combined:
  1. Trained ML composite engine (nlp_engine.py) - a phishing-tuned
     DistilBERT transformer + a TF-IDF/Logistic-Regression model trained
     on backend/data/email_text.csv. This is the primary signal: it
     generalizes to phrasing the regex list below was never written for.
  2. Curated keyword/regex cues (urgency / financial-diversion /
     authority-impersonation) - instant, fully explainable, zero
     dependency on the ML models being available. Used as supporting
     evidence in the summary, and as a fallback if the ML engine
     is somehow unavailable.

content_score = 0.65 * ML composite score (0-100)
              + 0.35 * regex cue score (0-100)

If ANTHROPIC_API_KEY is set, we ALSO ask Claude for a one-paragraph
plain-English explanation to show the analyst - this is a bonus
enrichment layer only, never the sole detector (a hosted LLM call is a
genuine privacy trade-off and is disclosed here explicitly).
"""
import re
import httpx

from ..config import settings
from . import nlp_engine

URGENCY_PHRASES = [
    r"act (now|immediately)", r"urgent(ly)?", r"immediate action required",
    r"account (will be|has been) (suspended|locked|closed)", r"verify your account",
    r"within 24 hours", r"final notice", r"failure to respond",
    r"limited time", r"expires? (today|soon)",
]

FINANCIAL_PHRASES = [
    r"wire transfer", r"bank (details|account) (has changed|update)",
    r"new payment (instructions|details)", r"invoice (attached|overdue|payment)",
    r"gift card", r"routing number", r"swift code", r"update your payroll",
    r"direct deposit", r"payment is overdue",
]

AUTHORITY_PHRASES = [
    r"\bceo\b", r"\bcfo\b", r"chief executive", r"managing director",
    r"this is (confidential|urgent) from", r"on behalf of the (ceo|director)",
    r"i need you to handle this discreetly", r"do not tell anyone",
]


def _scan(text: str, patterns: list) -> list:
    hits = []
    lower = text.lower()
    for pat in patterns:
        for m in re.finditer(pat, lower, re.IGNORECASE):
            hits.append(m.group(0))
    return hits


def _claude_explanation(subject: str, body: str, matched: dict, ml_summary: str) -> str:
    if not settings.ANTHROPIC_API_KEY:
        return ""
    prompt = (
        "You are a SOC analyst assistant. In 2-3 sentences, in plain English, "
        "explain why this email looks suspicious to a non-technical reader. "
        f"Subject: {subject}\nMatched suspicious phrases: {matched}\n"
        f"ML model finding: {ml_summary}\n"
        "Do not invent details not in the matches/finding. Be concise."
    )
    try:
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 200,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15.0,
        )
        data = r.json()
        blocks = data.get("content", [])
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    except Exception:
        return ""


def _build_flag_summary(status: str, ml: dict, matched: dict, top_words: list) -> str:
    """The human-readable 'why was this flagged' paragraph shown to the
    analyst the moment they click the NLP & Sentiment Analysis step."""
    combined_pct = round(ml["combined"]["total_nlp_score"] * 100, 1)
    transformer = ml["transformer"]
    tfidf = ml["tfidf"]

    if status == "green":
        return (
            f"No meaningful phishing/social-engineering signal was found. "
            f"The combined ML model score was only {combined_pct}%, well below "
            f"the flagging threshold, and no urgency, financial-diversion, or "
            f"authority-impersonation language was detected."
        )

    pieces = [f"This email was flagged with a combined NLP risk score of {combined_pct}%."]

    if ml["transformer_available"]:
        pieces.append(
            f"The phishing-detection transformer classified it as "
            f"'{transformer['prediction'].replace('_', ' ')}' with "
            f"{round(transformer['confidence'] * 100, 1)}% confidence."
        )
    else:
        pieces.append(
            "The transformer model was unavailable for this run, so the score "
            "relies on the locally trained model below."
        )

    pieces.append(
        f"The TF-IDF/Logistic-Regression model trained on the labelled email "
        f"dataset independently put the phishing probability at "
        f"{round(tfidf['phishing_prob'] * 100, 1)}%."
    )

    if top_words:
        pieces.append(f"The words most responsible for that score were: {', '.join(top_words)}.")

    cue_lines = []
    if matched["financial_diversion_cues"]:
        cue_lines.append(f"financial-diversion language ({', '.join(matched['financial_diversion_cues'])})")
    if matched["authority_impersonation_cues"]:
        cue_lines.append(f"authority/impersonation cues ({', '.join(matched['authority_impersonation_cues'])})")
    if matched["urgency_cues"]:
        cue_lines.append(f"urgency/pressure language ({', '.join(matched['urgency_cues'])})")
    if cue_lines:
        pieces.append(f"It also contains {'; '.join(cue_lines)}, a classic social-engineering pattern.")

    return " ".join(pieces)


def analyze_content(parsed_email) -> dict:
    text = f"{parsed_email.subject or ''}\n{parsed_email.body_text or ''}\n{parsed_email.body_html or ''}"
    # Models work best on a reasonably sized, cleaned slice of the email.
    model_input = text.strip()[:4000] or "(empty email body)"

    urgency_hits = _scan(text, URGENCY_PHRASES)
    financial_hits = _scan(text, FINANCIAL_PHRASES)
    authority_hits = _scan(text, AUTHORITY_PHRASES)

    matched = {
        "urgency_cues": sorted(set(urgency_hits)),
        "financial_diversion_cues": sorted(set(financial_hits)),
        "authority_impersonation_cues": sorted(set(authority_hits)),
    }

    regex_raw_score = (
        len(matched["urgency_cues"]) * 10
        + len(matched["financial_diversion_cues"]) * 20
        + len(matched["authority_impersonation_cues"]) * 20
    )
    regex_score = min(regex_raw_score, 100)

    ml = nlp_engine.analyze_text(model_input)
    ml_score = round(ml["combined"]["total_nlp_score"] * 100, 1)

    score = round(min(0.65 * ml_score + 0.35 * regex_score, 100), 1)

    if score >= 50:
        status = "red"
    elif score > 0:
        status = "amber"
    else:
        status = "green"

    findings = []
    if matched["financial_diversion_cues"]:
        findings.append(f"Financial-diversion language detected: {matched['financial_diversion_cues']}")
    if matched["authority_impersonation_cues"]:
        findings.append(f"Authority/impersonation cues detected: {matched['authority_impersonation_cues']}")
    if matched["urgency_cues"]:
        findings.append(f"Urgency/pressure language detected: {matched['urgency_cues']}")
    if ml["top_phishing_words"]:
        findings.append(f"ML model's top suspicious terms: {ml['top_phishing_words']}")
    if not findings:
        findings.append("No urgency, financial-diversion, or authority-impersonation language detected.")

    flag_summary = _build_flag_summary(status, ml, matched, ml["top_phishing_words"])

    llm_explanation = _claude_explanation(parsed_email.subject or "", text[:2000], matched, flag_summary)

    return {
        "step_key": "content",
        "title": "NLP Semantics & Social Engineering Analysis",
        "status": status,
        "summary": findings[0],
        "details": {
            "flag_summary": flag_summary,
            "ml_composite_score_pct": ml_score,
            "regex_cue_score_pct": regex_score,
            "transformer_result": ml["transformer"],
            "tfidf_result": ml["tfidf"],
            "transformer_available": ml["transformer_available"],
            "top_phishing_words": ml["top_phishing_words"],
            "matched_cues": matched,
            "findings": findings,
            "llm_explanation": llm_explanation or None,
            "llm_used": bool(llm_explanation),
            "manual_steps_this_replaces": [
                "Read the subject and body for pressure/urgency language",
                "Look for requests to change bank/payroll details",
                "Check for impersonation of a senior executive",
                "Run the message text through a phishing classifier",
            ],
        },
        "score": score,
    }
