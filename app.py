import streamlit as st
import requests
import pandas as pd
from datetime import datetime
import anthropic
from dotenv import load_dotenv
import os

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

st.set_page_config(
    page_title="AI Security Triage Dashboard",
    page_icon="🛡️",
    layout="wide"
)

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

col1, col2, col3, col4 = st.columns(4)

df = fetch_cves()

with col1:
    st.metric("Critical CVEs", len(df) if not df.empty else 0)
with col2:
    st.metric("Pending Review", len(df) if not df.empty else 0)
with col3:
    st.metric("Escalated", "0")
with col4:
    st.metric("Resolved Today", "0")

st.divider()

st.subheader("🔴 Critical Vulnerabilities — Pending Triage")


if not df.empty:
    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        st.write(f"**{len(df)} critical CVEs loaded from NIST NVD**")

    for idx, row in df.iterrows():
        with st.expander(f"🔴 {row['CVE ID']} — CVSS {row['CVSS Score']} — Published {row['Published']}"):
            st.write(f"**Description:** {row['Description']}")

            if st.button(f"Generate AI Triage Summary", key=f"triage_{idx}"):
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
                with col_b:
                    if st.button("⚠️ Escalate", key=f"escalate_{idx}"):
                        st.warning(f"⚠️ {row['CVE ID']} escalated to senior analyst.")
                with col_c:
                    if st.button("🔁 Override & Defer", key=f"defer_{idx}"):
                        st.info(f"🔁 {row['CVE ID']} deferred. Override logged.")
else:
    st.warning("No CVE data loaded. Check your connection.")