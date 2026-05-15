import streamlit as st
import requests
import pandas as pd
from datetime import datetime
import anthropic
from dotenv import load_dotenv
import os

load_dotenv()

# Works both locally and on Streamlit Cloud
api_key = os.getenv("ANTHROPIC_API_KEY")
if not api_key:
    try:
        api_key = st.secrets["ANTHROPIC_API_KEY"]
    except:
        st.error("ANTHROPIC_API_KEY not found. Add it to .env or Streamlit secrets.")
        st.stop()

client = anthropic.Anthropic(api_key=api_key)

st.set_page_config(
    page_title="AI Security Triage Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ── SESSION STATE INIT ────────────────────────────────────────────────────────

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "escalated_count" not in st.session_state:
    st.session_state.escalated_count = 0

if "resolved_count" not in st.session_state:
    st.session_state.resolved_count = 0

st.title("🛡️ AI Security Triage Dashboard")
st.caption("Enterprise threat and vulnerability decision-support with human-in-the-loop governance")

# ── CVE FEED ──────────────────────────────────────────────────────────────────

@st.cache_data(ttl=3600)
def fetch_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": 20,
        "startIndex": 0,
        "cvssV3Severity": "CRITICAL"
    }
    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        records = []
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")
            description = ""
            descs = cve.get("descriptions", [])
            for d in descs:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            metrics = cve.get("metrics", {})
            cvss_score = "N/A"
            cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if cvss_data:
                cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore", "N/A")
            published = cve.get("published", "")[:10]
            records.append({
                "CVE ID": cve_id,
                "Description": description[:200] + "..." if len(description) > 200 else description,
                "CVSS Score": cvss_score,
                "Published": published,
                "Status": "Pending Review"
            })
        df = pd.DataFrame(records)
        if not df.empty:
            df = df.sort_values("Published", ascending=False).reset_index(drop=True)
        return df
    except Exception as e:
        st.error(f"Error fetching CVE data: {e}")
        return pd.DataFrame()

# ── AI TRIAGE SUMMARY ─────────────────────────────────────────────────────────

def generate_triage_summary(cve_id, description, cvss_score):
    prompt = f"""You are a security analyst assistant. Analyze this vulnerability and provide a concise triage summary.

CVE ID: {cve_id}
CVSS Score: {cvss_score}
Description: {description}

Provide:
1. Risk Summary (1-2 sentences)
2. Recommended Action (Respond Now / Escalate / Monitor / Defer)
3. Rationale (1-2 sentences)
4. Confidence Score (High / Medium / Low)

Format your response clearly with these four labeled sections."""

    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

# ── MAIN LAYOUT ───────────────────────────────────────────────────────────────

df = fetch_cves()

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Critical CVEs", len(df) if not df.empty else 0)
with col2:
    st.metric("Pending Review", len(df) - len(st.session_state.audit_log) if not df.empty else 0)
with col3:
    st.metric("Escalated", st.session_state.escalated_count)
with col4:
    st.metric("Resolved Today", st.session_state.resolved_count)

st.divider()

st.subheader("🔴 Critical Vulnerabilities — Pending Triage")

if not df.empty:
    st.write(f"**{len(df)} critical CVEs loaded from NIST NVD**")

    for idx, row in df.iterrows():
        with st.expander(f"🔴 {row['CVE ID']} — CVSS {row['CVSS Score']} — Published {row['Published']}"):
            st.write(f"**Description:** {row['Description']}")

            if st.button("Generate AI Triage Summary", key=f"triage_{idx}"):
                with st.spinner("Analyzing vulnerability..."):
                    summary = generate_triage_summary(
                        row['CVE ID'],
                        row['Description'],
                        row['CVSS Score']
                    )
                    st.session_state[f"summary_{idx}"] = summary

            if f"summary_{idx}" in st.session_state:
                st.markdown("---")
                st.markdown("**🤖 AI Triage Summary:**")
                st.write(st.session_state[f"summary_{idx}"])

                st.markdown("**👤 Human Review Required:**")
                col_a, col_b, col_c = st.columns(3)

                with col_a:
                    if st.button("✅ Approve & Route", key=f"approve_{idx}"):
                        st.success(f"✅ {row['CVE ID']} approved and routed to response queue.")
                        st.session_state.audit_log.append({
                            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "CVE ID": row['CVE ID'],
                            "CVSS Score": row['CVSS Score'],
                            "AI Recommendation": "See summary above",
                            "Human Decision": "Approved & Routed",
                            "Rationale": "Analyst approved AI recommendation",
                            "Actioned By": "Analyst"
                        })
                        st.session_state.resolved_count += 1

                with col_b:
                    if st.button("⚠️ Escalate", key=f"escalate_{idx}"):
                        st.warning(f"⚠️ {row['CVE ID']} escalated to senior analyst.")
                        st.session_state.audit_log.append({
                            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "CVE ID": row['CVE ID'],
                            "CVSS Score": row['CVSS Score'],
                            "AI Recommendation": "See summary above",
                            "Human Decision": "Escalated",
                            "Rationale": "Analyst escalated to senior review",
                            "Actioned By": "Analyst"
                        })
                        st.session_state.escalated_count += 1

                with col_c:
                    override_reason = st.text_input(
                        "Override reason (required):",
                        key=f"override_reason_{idx}",
                        placeholder="Explain why you are deferring..."
                    )
                    if st.button("🔁 Override & Defer", key=f"defer_{idx}"):
                        if override_reason:
                            st.info(f"🔁 {row['CVE ID']} deferred. Override logged.")
                            st.session_state.audit_log.append({
                                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "CVE ID": row['CVE ID'],
                                "CVSS Score": row['CVSS Score'],
                                "AI Recommendation": "See summary above",
                                "Human Decision": "Override & Deferred",
                                "Rationale": override_reason,
                                "Actioned By": "Analyst"
                            })
                        else:
                            st.error("Override reason is required before deferring.")
else:
    st.warning("No CVE data loaded. Check your connection.")

# ── THREAT INDICATORS ─────────────────────────────────────────────────────────

st.divider()
st.subheader("🌐 Active Threat Indicators — URL Intelligence Feed")

@st.cache_data
def load_threat_indicators():
    try:
        import json
        with open("data/threat_indicators.json", "r") as f:
            data = json.load(f)
        return pd.DataFrame(data["indicators"])
    except Exception as e:
        st.error(f"Error loading threat indicators: {e}")
        return pd.DataFrame()

def generate_url_analysis(url, threat_type, severity):
    prompt = f"""You are a security analyst reviewing a malicious URL indicator. Analyze this threat and provide a response recommendation.

URL: {url}
Threat Type: {threat_type}
Severity: {severity}

Provide:
1. Threat Summary (1-2 sentences describing what this URL likely does)
2. Recommended Action (Block Immediately / Investigate / Monitor)
3. Affected Systems (what enterprise assets are most at risk)
4. Mitigation Steps (2-3 specific actions to take)
5. Confidence Score (High / Medium / Low)

Format your response clearly with these five labeled sections."""

    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

indicators_df = load_threat_indicators()

if not indicators_df.empty:
    critical_count = len(indicators_df[indicators_df['severity'] == 'Critical'])
    high_count = len(indicators_df[indicators_df['severity'] == 'High'])

    col_i1, col_i2, col_i3 = st.columns(3)
    with col_i1:
        st.metric("Total Indicators", len(indicators_df))
    with col_i2:
        st.metric("Critical", critical_count)
    with col_i3:
        st.metric("High", high_count)

    st.write(f"**{len(indicators_df)} active threat indicators loaded**")

    for idx, row in indicators_df.iterrows():
        severity_icon = "🔴" if row['severity'] == "Critical" else "🟠" if row['severity'] == "High" else "🟡"
        with st.expander(f"{severity_icon} {row['type']} — {row['url']} — Reported {row['reported']}"):
            st.write(f"**URL:** `{row['url']}`")
            st.write(f"**Type:** {row['type']}")
            st.write(f"**Severity:** {row['severity']}")
            st.write(f"**Reported:** {row['reported']}")

            if st.button("Generate Threat Analysis", key=f"url_{idx}"):
                with st.spinner("Analyzing threat indicator..."):
                    analysis = generate_url_analysis(
                        row['url'],
                        row['type'],
                        row['severity']
                    )
                    st.session_state[f"url_analysis_{idx}"] = analysis

            if f"url_analysis_{idx}" in st.session_state:
                st.markdown("---")
                st.markdown("**🤖 AI Threat Analysis:**")
                st.write(st.session_state[f"url_analysis_{idx}"])

                st.markdown("**👤 Analyst Decision Required:**")
                col_a, col_b, col_c = st.columns(3)

                with col_a:
                    if st.button("🚫 Block Immediately", key=f"url_block_{idx}"):
                        st.error(f"🚫 {row['url']} blocked.")
                        st.session_state.audit_log.append({
                            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "CVE ID": f"URL-{idx + 1}",
                            "CVSS Score": row['severity'],
                            "AI Recommendation": "Block Immediately",
                            "Human Decision": "Blocked",
                            "Rationale": f"Analyst blocked {row['type']} indicator",
                            "Actioned By": "Analyst"
                        })
                        st.session_state.resolved_count += 1

                with col_b:
                    if st.button("🔍 Investigate", key=f"url_investigate_{idx}"):
                        st.warning(f"🔍 {row['url']} flagged for investigation.")
                        st.session_state.audit_log.append({
                            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "CVE ID": f"URL-{idx + 1}",
                            "CVSS Score": row['severity'],
                            "AI Recommendation": "Investigate",
                            "Human Decision": "Under Investigation",
                            "Rationale": "Analyst initiated investigation",
                            "Actioned By": "Analyst"
                        })
                        st.session_state.escalated_count += 1

                with col_c:
                    url_override = st.text_input(
                        "Override reason (required):",
                        key=f"url_override_{idx}",
                        placeholder="Explain why this is a false positive..."
                    )
                    if st.button("✅ False Positive", key=f"url_fp_{idx}"):
                        if url_override:
                            st.success(f"✅ {row['url']} marked as false positive.")
                            st.session_state.audit_log.append({
                                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "CVE ID": f"URL-{idx + 1}",
                                "CVSS Score": row['severity'],
                                "AI Recommendation": "Block Immediately",
                                "Human Decision": "False Positive",
                                "Rationale": url_override,
                                "Actioned By": "Analyst"
                            })
                        else:
                            st.error("Override reason required.")
else:
    st.warning("No threat indicators loaded. Check data/threat_indicators.json exists.")

# ── AUDIT LOG ─────────────────────────────────────────────────────────────────

st.divider()
st.subheader("📋 Audit Log — All Decisions This Session")

if st.session_state.audit_log:
    audit_df = pd.DataFrame(st.session_state.audit_log)
    st.dataframe(audit_df, use_container_width=True)

    csv = audit_df.to_csv(index=False)
    st.download_button(
        label="⬇️ Download Audit Log (CSV)",
        data=csv,
        file_name=f"audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )
else:
    st.info("No decisions logged yet. Triage a CVE above to begin.")

# ── PHISHING EMAIL TRIAGE ─────────────────────────────────────────────────────

st.divider()
st.subheader("📧 Phishing Email Triage — AI-Assisted Analysis")

@st.cache_data
def load_phishing_data():
    try:
        df = pd.read_csv("data/phishing_email.csv")
        phishing = df[df['label'] == 1].head(10).reset_index(drop=True)
        return phishing
    except Exception as e:
        st.error(f"Error loading phishing data: {e}")
        return pd.DataFrame()

def generate_phishing_summary(email_text):
    prompt = f"""You are a security analyst reviewing a potential phishing email. Analyze this email content and provide a triage summary.

Email Content:
{email_text[:500]}

Provide:
1. Threat Assessment (1-2 sentences describing the phishing indicators)
2. Risk Level (Critical / High / Medium / Low)
3. Recommended Action (Block & Quarantine / Escalate to SOC / Flag for Review / Monitor)
4. Key Indicators (2-3 specific phishing signals you identified)
5. Confidence Score (High / Medium / Low)

Format your response clearly with these five labeled sections."""

    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

phishing_df = load_phishing_data()

if not phishing_df.empty:
    st.write(f"**{len(phishing_df)} phishing emails loaded for triage**")

    for idx, row in phishing_df.iterrows():
        email_preview = str(row['text_combined'])[:150] + "..."
        with st.expander(f"📧 Phishing Email #{idx + 1} — {email_preview}"):
            st.write(f"**Email Content Preview:**")
            st.write(str(row['text_combined'])[:500])

            if st.button("Generate Phishing Analysis", key=f"phishing_{idx}"):
                with st.spinner("Analyzing email..."):
                    summary = generate_phishing_summary(str(row['text_combined']))
                    st.session_state[f"phishing_summary_{idx}"] = summary

            if f"phishing_summary_{idx}" in st.session_state:
                st.markdown("---")
                st.markdown("**🤖 AI Phishing Analysis:**")
                st.write(st.session_state[f"phishing_summary_{idx}"])

                st.markdown("**👤 Analyst Decision Required:**")
                col_a, col_b, col_c = st.columns(3)

                with col_a:
                    if st.button("🚫 Block & Quarantine", key=f"block_{idx}"):
                        st.error(f"🚫 Email #{idx + 1} blocked and quarantined.")
                        st.session_state.audit_log.append({
                            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "CVE ID": f"PHISH-{idx + 1}",
                            "CVSS Score": "N/A",
                            "AI Recommendation": "Block & Quarantine",
                            "Human Decision": "Blocked & Quarantined",
                            "Rationale": "Analyst confirmed phishing — blocked",
                            "Actioned By": "Analyst"
                        })
                        st.session_state.resolved_count += 1

                with col_b:
                    if st.button("⚠️ Escalate to SOC", key=f"phish_escalate_{idx}"):
                        st.warning(f"⚠️ Email #{idx + 1} escalated to SOC.")
                        st.session_state.audit_log.append({
                            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "CVE ID": f"PHISH-{idx + 1}",
                            "CVSS Score": "N/A",
                            "AI Recommendation": "Escalate to SOC",
                            "Human Decision": "Escalated to SOC",
                            "Rationale": "Analyst escalated for deeper investigation",
                            "Actioned By": "Analyst"
                        })
                        st.session_state.escalated_count += 1

                with col_c:
                    phish_override = st.text_input(
                        "Override reason (required):",
                        key=f"phish_override_{idx}",
                        placeholder="Explain why you are releasing this email..."
                    )
                    if st.button("✅ Release — False Positive", key=f"release_{idx}"):
                        if phish_override:
                            st.success(f"✅ Email #{idx + 1} released. Override logged.")
                            st.session_state.audit_log.append({
                                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "CVE ID": f"PHISH-{idx + 1}",
                                "CVSS Score": "N/A",
                                "AI Recommendation": "Block & Quarantine",
                                "Human Decision": "Released — False Positive",
                                "Rationale": phish_override,
                                "Actioned By": "Analyst"
                            })
                        else:
                            st.error("Override reason required before releasing.")
else:
    st.warning("No phishing data loaded. Check data/phishing_email.csv exists.")