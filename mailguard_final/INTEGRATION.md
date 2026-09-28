# Integration package — mailguard_final ↔ part3_starter, + PII-masked Gemini summaries

Everything in this zip is **new, standalone files**. Nothing in
`mailguard_final/` or `part3_starter/` was changed, and neither was
`nlp_engine.py` or `content_module.py`'s ML/NLP scoring — those keep
computing fraud/risk scores exactly as before. Tested against your
real `sample_emails/phishing_sample1.eml` and against part3's actual
`ingest_bundle()` before packaging (see "What I tested" below).

## Files

| File | Goes in | What it does |
|---|---|---|
| `adapters.py` | `mailguard_final/backend/app/` | Translates a `run_pipeline()` result into the exact bundle shape `part3_starter/sample_bundle.json` defines |
| `bridge.py` | `mailguard_final/backend/app/` | Calls `adapters.py`, then either writes the bundle to a JSON file or live-ingests it into part3's DB |
| `summarizer.py` | `mailguard_final/backend/app/` | PII masking + Gemini summarization, fully standalone |
| `demo_bridge.py` | `mailguard_final/backend/app/` | Test script — runs the above against one `.eml`, no FastAPI/DB needed |

## What YOU need to add (I didn't touch these — your call)

### 1. One import + one line in `routers/emails.py`

At the top:
```python
from ..bridge import send_to_part3
```

Inside `upload_email()`, right after `result = run_pipeline(raw_bytes, file.filename)`:
```python
send_to_part3(result, file.filename, raw_bytes)
```

That's the entire hook. It's safe to add — if `PART3_MODE=file` (the
default) it just writes a JSON file; it never touches your DB writes
or the response you already return.

### 2. Config (`.env` / `config.py`)

Add whichever of these you need — nothing here is required for
mailguard_final's own tests to keep passing:

```
# --- part3 bridge ---
PART3_MODE=file                    # or "live"
PART3_BUNDLE_DIR=./part3_bundles   # used when PART3_MODE=file
PART3_DB_PATH=./part3.db           # used when PART3_MODE=live
PART3_PACKAGE_DIR=../part3_starter/part3   # used when PART3_MODE=live

# --- Gemini summarizer ---
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-2.5-flash
```

### 3. Where to actually call the summarizer

Not wired in anywhere — it's a plain function, call it wherever you
want the summary to show up (an analyst-facing field, a new API
endpoint, inside `content_module.py`'s output, etc.):

```python
from .summarizer import summarize_with_gemini
result = summarize_with_gemini(parsed_email.body_text)
# result = {"summary": "...", "summary_masked": "...", "pii_entities_masked": 2}
```

I left this decision to you on purpose since it touches
`content_module.py`, which you said not to change without asking.

## One judgment call, flagged (see `adapters.py` docstring)

mailguard's `auth_module.py` checks whether SPF/DMARC records are
*published* for a domain and whether a DKIM header is *present* — not
a true per-message pass/fail/alignment check. `build_bundle()` maps:

- `spf_record_found: bool` → `"pass"`/`"fail"`
- `dmarc_record_found: bool` → `"pass"`/`"fail"`
- `has_dkim_signature: bool` → `"pass"`/`"none"`

This is the most defensible reading, not a verified equivalence —
worth a line in your report as a stated limitation. If you'd rather
map it differently, that logic lives entirely in `build_bundle()`.

## PART3_MODE: `file` vs `live`

- **`file` (default):** writes each bundle as `<sha256>.json` into
  `PART3_BUNDLE_DIR`. Drag those into part3's own Streamlit sidebar
  uploader (`streamlit run app.py`) — it already accepts exactly this
  format. Zero risk to either codebase; nothing shares a process or DB.
- **`live`:** imports `part3_starter/part3` directly and calls its own
  `ingest_bundle()` against a shared SQLite file, so every mailguard
  upload auto-populates part3's graph. Needs `PART3_PACKAGE_DIR` to
  point at part3's package folder, and both apps' dependencies
  (`reportlab`, `networkx`, etc.) importable in the same environment.

Start with `file` while you're testing; switch to `live` for the demo
if you want the "upload once, see it in both dashboards" effect.

## PII masking — how it works

`mask_pii(text)` finds emails, phone numbers, IPs, URLs, and
card-like numbers with regex, and replaces each with a stable
placeholder (`[EMAIL_1]`, `[PHONE_1]`, ...). The same value always
gets the same placeholder within one call, so repeated mentions stay
coherent in the summary. The placeholder → real-value mapping is a
plain Python dict that never leaves the function call — only the
masked text is sent to Gemini.

`summarize_with_gemini(text)` does mask → call Gemini → unmask, and
returns both the masked and unmasked versions so you can show
whichever is appropriate in the UI.

This is regex-based, matching the style `link_module.py` already uses
elsewhere in your codebase — fast and dependency-free. It won't catch
names or physical addresses (those aren't pattern-shaped). If you
want that level of coverage for your report, `pip install
presidio-analyzer presidio-anonymizer` is the standard library for
it — swapping `mask_pii()`'s internals for Presidio calls wouldn't
change `summarize_with_gemini()` at all, since it only depends on
the `(masked_text, mapping)` return shape.

## What I tested before packaging

1. `build_bundle()` against your real `sample_emails/phishing_sample1.eml`
   parsed through your actual `email_parser.parse_eml()` — correct
   SHA-256, correct UTC timestamp conversion, correct ASN parsing
   (`"AS45102 Alibaba"` → `45102`/`"Alibaba"`), correct HTML stripping.
2. The resulting bundle fed into part3_starter's **real**
   `ingest.ingest_bundle()` — ingested with no errors, correct
   `from_addr` and `risk_score` stored.
3. `mask_pii()` / `unmask()` round-trip on text containing an email,
   a URL, and a phone number — full round-trip match confirmed.

I did not test the live Gemini API call itself (no key available
here) — `summarize_with_gemini()` will return
`{"summary": None, "error": "GEMINI_API_KEY not set"}` until you add
one.

## Run the demo yourself

```bash
cd mailguard_final/backend
# copy the 4 files from this zip into app/ first
python -m app.demo_bridge sample_emails/phishing_sample1.eml
```

Prints the fraud score (unchanged), the built bundle, and the
before/after of PII masking on the email body.
