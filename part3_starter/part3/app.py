"""Part 3 investigation workbench (Streamlit). Run: streamlit run app.py"""
import json, os
import streamlit as st
import tempfile
from part3 import db, ingest, explain, ledger, pipeline, dossier, actions, stix_export

st.set_page_config(page_title="Part 3 Investigation Workbench", layout="wide")

@st.cache_resource
def get_conn():
    os.makedirs("data", exist_ok=True)
    return db.connect("data/part3.db", check_same_thread=False)

conn = get_conn()
q = lambda sql, *a: conn.execute(sql, a).fetchall()

# ---------------- sidebar ----------------
st.sidebar.header("Analyst")
analyst = st.sidebar.text_input("Your name (recorded with every action)", value="analyst", key="analyst")
st.sidebar.header("Data")
if st.sidebar.button("Load demo data (fictional)"):
    pipeline.load_demo(conn)
    st.sidebar.success("Demo loaded")
files = st.sidebar.file_uploader("Or upload analysis bundles (.json from Parts 1 and 2)", type="json", accept_multiple_files=True)
if files and st.sidebar.button("Ingest uploaded bundles and correlate"):
    for f in files:
        try:
            ingest.ingest_bundle(conn, json.load(f))
        except Exception as e:
            st.sidebar.error("%s: %s" % (f.name, e))
    pipeline.run_all(conn)
    st.sidebar.success("Done")
n_email = q("SELECT COUNT(*) FROM emails")[0][0]
n_camp = q("SELECT COUNT(*) FROM campaigns")[0][0]
st.sidebar.metric("Emails", n_email); st.sidebar.metric("Campaigns", n_camp)
st.sidebar.caption("Confidence values are algorithmic assessments, not legal proof.")

st.title("Investigation Workbench")

def flash(msg):
    st.session_state["flash"] = msg
    st.rerun()

if "flash" in st.session_state:
    st.success(st.session_state.pop("flash"))
if n_email == 0:
    st.info("No data yet. Click **Load demo data** in the sidebar.")
    st.stop()

tab1, tab2, tab3, tab4, tab5 = st.tabs(["Campaigns", "Why linked?", "Timeline", "Evidence and custody", "Dossier"])
campaigns = [r["campaign_id"] for r in q("SELECT campaign_id FROM campaigns ORDER BY size DESC, campaign_id")]

# ---------------- tab 1: campaigns ----------------
with tab1:
    if not campaigns:
        st.warning("No campaigns formed yet.")
    else:
        cid = st.selectbox("Campaign", campaigns, key="cid")
        c = q("SELECT * FROM campaigns WHERE campaign_id=?", cid)[0]
        m1, m2, m3 = st.columns(3)
        m1.metric("Members", c["size"]); m2.metric("Status", c["status"]); m3.metric("Method", c["algorithm_version"])
        if c["notes"]:
            st.warning(c["notes"])
        st.markdown("**Analyst decision on this campaign**")
        cc = st.text_input("Comment (required)", key="camp_comment")
        b1, b2 = st.columns(2)
        for col, act, label in ((b1, "confirm_campaign", "Confirm campaign"), (b2, "reject_campaign", "Reject campaign")):
            if col.button(label, key=act):
                try:
                    actions.record_campaign_action(conn, analyst, act, cid, cc)
                    flash("%s: %s recorded." % (cid, label))
                except ValueError as ex:
                    st.error(str(ex))
        summ = explain.campaign_summary(conn, cid)
        cols = st.columns(3)
        for col, (kind, label) in zip(cols, [("ip", "Originating IPs"), ("domain", "Landing domains"), ("hash", "Attachment hashes")]):
            col.subheader(label)
            col.dataframe([{"value": v, "emails": n} for v, n in summ["shared"][kind]], hide_index=True)
        st.subheader("Members")
        mem = q("SELECT c.email_id, e.received_at, e.from_addr, e.risk_score, c.confidence FROM campaign_members c "
                "JOIN emails e USING (email_id) WHERE c.campaign_id=? ORDER BY c.confidence DESC, e.received_at", cid)
        st.dataframe([dict(r) for r in mem], hide_index=True)
        st.subheader("Link graph")
        ids = {r["email_id"] for r in mem}
        dot = ["graph G { layout=neato; overlap=false; node [shape=circle, style=filled, fillcolor=\"#E6F4F5\", fontsize=9];"]
        for r in mem:
            dot.append('"%s" [label="%s"];' % (r["email_id"], r["email_id"][-4:]))
        for r in q("SELECT from_id, to_id, confidence, strength FROM relationships WHERE type='LINKED_TO'"):
            if r["from_id"] in ids and r["to_id"] in ids:
                style = "solid" if r["strength"] == "hard" else "dashed"
                dot.append('"%s" -- "%s" [style=%s, penwidth=%.1f, color="%s"];' % (
                    r["from_id"], r["to_id"], style, 0.5 + 2 * r["confidence"], "#0E7C86" if r["strength"] == "hard" else "#C97A00"))
        dot.append("}")
        st.graphviz_chart("\n".join(dot))
        st.subheader("Export")
        if st.button("Generate STIX 2.1 bundle", key="stix_btn"):
            with tempfile.TemporaryDirectory() as tmp:
                res = stix_export.export(conn, cid, os.path.join(tmp, "%s_stix.json" % cid))
            st.session_state["stix"] = (res["text"], res["sha256"], res["objects"], res["indicators"], cid)
        if st.session_state.get("stix", (0, 0, 0, 0, None))[4] == cid:
            stx, sha, n_obj, n_ind, _ = st.session_state["stix"]
            st.success("STIX bundle for %s: %d objects, %d indicators. SHA-256 recorded in the custody ledger (EXPORTED)." % (cid, n_obj, n_ind))
            if n_ind == 0:
                st.caption("No indicators: they are only created after an analyst confirms the campaign, and never for shared IPs.")
            st.code("SHA-256: " + sha)
            st.download_button("Download STIX JSON", stx, file_name="%s_stix.json" % cid, mime="application/json")
        st.caption("Solid teal = link includes an exact match (hard). Dashed amber = similarity only (soft). Thicker = higher score.")

# ---------------- tab 2: why linked ----------------
with tab2:
    all_ids = [r["email_id"] for r in q("SELECT email_id FROM emails ORDER BY received_at, email_id")]
    c1, c2 = st.columns(2)
    a = c1.selectbox("Email A", all_ids, index=0, key="wa")
    b = c2.selectbox("Email B", all_ids, index=min(1, len(all_ids) - 1), key="wb")
    if a == b:
        st.info("Pick two different emails.")
    else:
        d = explain.why_linked(conn, a, b)
        if d is None:
            st.write("No link and no notable shared signals recorded for this pair.")
        else:
            (st.success if d["decision"] == "linked" else st.error)("%s | score %.2f | %s" % (d["decision"].upper(), d["score"], d["reason"]))
            st.dataframe([{"signal": k, "value": v["value"], "weight": v["weight"], "contribution": v["contribution"]}
                          for k, v in sorted(d["signals"].items(), key=lambda kv: -kv[1]["contribution"])], hide_index=True)
            if d["hard_signals"]:
                st.write("**Exact matches (hard):** " + "; ".join(d["hard_signals"]))
            st.caption("Method %s. Weights are placeholders until tuned on real data." % d["method"])

    if a != b:
        d2 = explain.why_linked(conn, a, b)
        st.markdown("**Analyst decision on this pair**")
        if d2 and d2.get("analyst"):
            an = d2["analyst"]
            st.info("Last action: %s by %s at %s. Comment: %s" % (an["action"], an["analyst"], an["ts"], an["comment"]))
        lc = st.text_input("Comment (required)", key="link_comment")
        x1, x2 = st.columns(2)
        for col, act, label in ((x1, "confirm_link", "Confirm / add link"), (x2, "reject_link", "Reject link")):
            if col.button(label, key=act):
                try:
                    actions.record_link_action(conn, analyst, act, a, b, lc)
                    pipeline.recluster(conn)
                    flash("%s recorded and campaigns re-formed." % label)
                except ValueError as ex:
                    st.error(str(ex))
        st.caption("Original algorithmic scores are kept; your decision is stored separately with your name and comment, and logged in the custody ledger.")

# ---------------- tab 3: timeline ----------------
with tab3:
    if campaigns:
        tcid = st.selectbox("Campaign", campaigns, key="tcid")
        st.dataframe(explain.timeline(conn, tcid), hide_index=True)
    else:
        st.info("Form a campaign first.")

# ---------------- tab 4: evidence and custody ----------------
with tab4:
    eid = st.selectbox("Email", all_ids, key="eid")
    art = q("SELECT a.* FROM artifacts a JOIN emails e USING (artifact_id) WHERE e.email_id=?", eid)[0]
    st.write("**Evidence ID:** %s  |  **File:** %s  |  **Size:** %s bytes  |  **Collected:** %s" % (art["evidence_id"], art["filename"], art["size_bytes"], art["collected_at"]))
    st.code("SHA-256: " + art["sha256"])
    ev = q("SELECT seq, type, actor, ts, substr(prev_hash,1,12) AS prev_hash, substr(event_hash,1,12) AS event_hash FROM custody_events WHERE evidence_id=? ORDER BY seq", art["evidence_id"])
    st.dataframe([dict(r) for r in ev], hide_index=True)
    if st.button("Verify custody chain"):
        ok, bad = ledger.verify(conn, art["evidence_id"])
        st.success("Chain intact: every event hash matches.") if ok else st.error("Chain BROKEN at event %s." % bad)
    with st.expander("Demo: simulate tampering (changes are rolled back)"):
        if st.button("Edit event 2, then verify"):
            conn.execute("UPDATE custody_events SET actor='someone-else' WHERE evidence_id=? AND seq=2", (art["evidence_id"],))
            ok, bad = ledger.verify(conn, art["evidence_id"])
            conn.rollback()
            st.error("Tampering detected: chain broken at event %s." % bad) if not ok else st.warning("Not detected (unexpected).")
    st.markdown("**Analyst comment on this email**")
    ec = st.text_input("Comment", key="email_comment")
    if st.button("Add comment", key="add_comment"):
        try:
            actions.record_comment(conn, analyst, eid, ec)
            flash("Comment recorded (see the custody log).")
        except ValueError as ex:
            st.error(str(ex))
    st.caption("The chain is tamper-evident, not tamper-proof, and does not by itself make evidence admissible.")

# ---------------- tab 5: dossier ----------------
with tab5:
    st.write("Generates the forensic dossier (PDF) for one email and its campaign, from stored data only.")
    default = 0
    if campaigns:
        first = q("SELECT email_id FROM campaign_members WHERE campaign_id=? ORDER BY confidence DESC LIMIT 1", campaigns[0])
        if first and first[0][0] in all_ids: default = all_ids.index(first[0][0])
    did = st.selectbox("Email", all_ids, index=default, key="did")
    if st.button("Generate dossier"):
        with tempfile.TemporaryDirectory() as tmp:
            res = dossier.generate(conn, did, os.path.join(tmp, "dossier_%s.pdf" % did))
            st.session_state["dossier"] = (open(res["path"], "rb").read(), res["sha256"], did)
    if "dossier" in st.session_state:
        data, sha, d_email = st.session_state["dossier"]
        st.success("Dossier for %s generated. Its SHA-256 was recorded in the custody ledger (EXPORTED)." % d_email)
        st.code("SHA-256: " + sha)
        st.download_button("Download PDF", data, file_name="dossier_%s.pdf" % d_email, mime="application/pdf")
