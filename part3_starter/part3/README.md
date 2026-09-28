# Part 3 starter: campaign correlation, evidence and custody (SIH 2026, PS 106)

Runs standalone on fake data, so Part 3 can be built while Parts 1 and 2 are still in progress.

## Run it
    pip install -r requirements.txt
    python run_demo.py        # full demo: ingest, correlate, campaign, "why linked", custody tamper test
    python -m pytest -q tests # 13 tests
    streamlit run app.py      # analyst workbench in the browser (click 'Load demo data' in the sidebar; enter your name in the sidebar first)
    streamlit run app.py      # analyst page

## What each file does
- `part3/ingest.py`   reads one analysis bundle (Part 1 + Part 2 output), stores the evidence record and graph edges
- `part3/correlate.py` scores every pair of emails (infrastructure, URL, content, attachment, identity, time) with reasons
- `part3/cluster.py`  groups strong links into campaigns (connected components, checked with Louvain) and gives each email a confidence
- `part3/explain.py`  "why linked?" text and campaign summary
- `part3/ledger.py`   hash-chained custody log with a verify function
- `app.py`            Streamlit workbench: Campaigns (shared infrastructure, members, link graph), Why linked?, Timeline, Evidence and custody (verify + tamper demo)
- `part3/actions.py`  analyst actions: confirm/reject a link, comment, confirm/reject a campaign. Each needs a comment, is stored with the analyst's name, and is logged in the custody ledger. Original algorithmic scores are never deleted
- `part3/stix_export.py` exports a campaign as a STIX 2.1 bundle (observed-data, observables, campaign with confidence and evidence IDs, shared infrastructure). Indicators are created only for analyst-confirmed campaigns and never for shared IPs; no email body text is exported
- `part3/dossier.py`  builds the forensic dossier PDF (case summary, evidence identity, findings with evidence IDs, timeline, limitations, custody ledger, draft certificate fields) and records its SHA-256 as an EXPORTED custody event
- `part3/pipeline.py`  helpers the app uses (load demo, run correlation + clustering)
- `part3/db.py`       SQLite tables (same design as the research guide, so it can move to PostgreSQL later)
- `part3/demo_data.py` fictional test emails: 15 campaign emails, 3 look-alikes on the same shared IP, 5 normal emails
- `sample_bundle.json` the exact format Parts 1 and 2 must hand to Part 3

## The hand-off contract (what Parts 1 and 2 must output per email)
See `sample_bundle.json`. Required: `artifact.sha256`, `email.received_at` (UTC, `YYYY-MM-DDTHH:MM:SSZ`), `email.from_addr`,
`email.body_norm` (cleaned text), `part1.trust_boundary_ip`, `part2.asn`, `part2.urls[].final_domain`, `part2.attachments[].sha256`.

## Honest notes
- Weights and the threshold in `correlate.py` are placeholders tuned on fake data. Re-tune on real labelled data.
- Correlation groups *similar* email, not *malicious* email. The 3 bakery newsletters form their own group (CMP-002); the Part 2 risk score is what tells them apart.
- CMP-001 carries a REVIEW note (community detection sees sub-groups). That is the built-in check for "one weak link merged two campaigns".
- The custody log is tamper-evident, not tamper-proof, and does not by itself make evidence admissible.

## Analyst page
    streamlit run app.py
Tabs: Overview, Graph, Why linked?, Timeline, Evidence and custody. Sidebar: demo data, or upload real bundle `.json` files from Parts 1 and 2.
