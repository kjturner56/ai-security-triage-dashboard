import streamlit as st
import requests
import pandas as pd
from datetime import datetime
import anthropic
from dotenv import load_dotenv
import os
import json

load_dotenv()

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
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── SESSION STATE ─────────────────────────────────────────────────────────────

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []
if "escalated_count" not in st.session_state:
    st.session_state.escalated_count = 0
if "resolved_count" not in st.session_state:
    st.session_state.resolved_count = 0

# ── STYLING ───────────────────────────────────────────────────────────────────

st.markdown("""
<style>
/* Force dark theme */
[data-testid="stAppViewContainer"] {
    background-color: #0e1117;
}
[data-testid="stAppViewContainer"] > .main {
    background-color: #0e1117;
}
header[data-testid="stHeader"] {
    background-color: #0e1117;
}
[data-testid="stSidebar"] {
    background-color: #1a1f2e;
}

/* Tab styling */
.stTabs [data-baseweb="tab-list"] {
    background-color: #1a1f2e;
    padding: 0.5rem;
    border-radius: 8px;
    margin-bottom: 1rem;
}
.stTabs [data-baseweb="tab"] {
    color: #a8b2d8;
    font-weight: 500;
}
.stTabs [aria-selected="true"] {
    color: #ffffff;
    background-color: #2d3561;
    border-radius: 6px;
    border-bottom-color: #e63946;
}

/* Dashboard header */
.dashboard-header {
    background: linear-gradient(135deg, #1a1f2e 0%, #2d3561 100%);
    padding: 2rem;
    border-radius: 12px;
    margin-bottom: 1.5rem;
    border-left: 4px solid #e63946;
}
.dashboard-title {
    font-size: 2rem;
    font-weight: 700;
    color: #ffffff;
    margin: 0;
}
.dashboard-subtitle {
    font-size: 0.95rem;
    color: #a8b2d8;
    margin-top: 0.3rem;
}

/* AI summary box */
.insight-box {
    background: linear-gradient(135deg, #1e3a2f 0%, #1a2e3d 100%);
    border: 1px solid #2d6a4f;
    border-left: 4px solid #52b788;
    padding: 1rem 1.5rem;
    border-radius: 8px;
    margin-bottom: 1.5rem;
}
.insight-title {
    color: #52b788;
    font-weight: 600;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 0.3rem;
}
.insight-text {
    color: #e8f4ea;
    font-size: 1rem;
}

/* AI triage result box */
.triage-box {
    background: #1a2035;
    border: 1px solid #2d3561;
    border-left: 4px solid #4361ee;
    border-radius: 8px;
    padding: 1rem 1.2rem;
    margin: 0.5rem 0 1rem 0;
    font-family: monospace;
    font-size: 0.88rem;
    color: #c8d0e8;
    white-space: pre-wrap;
    line-height: 1.6;
}

/* Section headers */
.section-header {
    font-size: 1.2rem;
    font-weight: 600;
    color: #e2e8f0;
    padding: 0.5rem 0;
    border-bottom: 2px solid #e63946;
    margin-bottom: 1rem;
}

/* Governance note */
.governance-note {
    background: #1a2035;
    border: 1px solid #2d3561;
    border-radius: 8px;
    padding: 0.8rem 1.2rem;
    margin-bottom: 1rem;
    font-size: 0.85rem;
    color: #a8b2d8;
}

</style>
""", unsafe_allow_html=True)

# ── HEADER ────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="dashboard-header">
    <p class="dashboard-title">🛡️ AI Security Triage Dashboard</p>
    <p class="dashboard-subtitle">
        Enterprise threat and vulnerability decision-support &nbsp;·&nbsp;
        Human-in-the-loop governance &nbsp;·&nbsp;
        Kenneth R. Turner &nbsp;·&nbsp;
        <a href="https://kenturnerportfolio.com" style="color:#7eb8f7;">kenturnerportfolio.com</a>
    </p>
</div>
""", unsafe_allow_html=True)

# ── DATA LOADING ──────────────────────────────────────────────────────────────

from datetime import datetime, timedelta

@st.cache_data(ttl=3600)
def fetch_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Pull last 90 days only
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=90)
    
    params = {
        "resultsPerPage": 20,
        "startIndex": 0,
        "cvssV3Severity": "CRITICAL",
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
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
            for d in cve.get("descriptions", []):
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
            df = df[df['CVSS Score'].apply(
                lambda x: float(x) >= 9.0 if x != 'N/A' else False
            )].reset_index(drop=True)
            df = df[df['CVE ID'].str.extract(r'CVE-(\d{4})')[0].astype(int) >= 2024].reset_index(drop=True)
        return df
    except Exception as e:
        st.error(f"Error fetching CVE data: {e}")
        return pd.DataFrame()

@st.cache_data
def load_threat_indicators():
    try:
        with open("data/threat_indicators.json", "r") as f:
            data = json.load(f)
        return pd.DataFrame(data["indicators"])
    except:
        return pd.DataFrame()

@st.cache_data
def load_phishing_data():
    try:
        df = pd.read_csv("data/phishing_sample.csv")
        return df[df['label'] == 1].head(10).reset_index(drop=True)
    except:
        return pd.DataFrame()

df = fetch_cves()
indicators_df = load_threat_indicators()
phishing_df = load_phishing_data()

critical_url = len(indicators_df[indicators_df['severity'] == 'Critical']) if not indicators_df.empty else 0
high_url = len(indicators_df[indicators_df['severity'] == 'High']) if not indicators_df.empty else 0
total_threats = (len(df) if not df.empty else 0) + \
                (len(indicators_df) if not indicators_df.empty else 0) + \
                (len(phishing_df) if not phishing_df.empty else 0)
pending = total_threats - len(st.session_state.audit_log)

# ── AI FUNCTIONS ──────────────────────────────────────────────────────────────

PLAIN_TEXT_INSTRUCTION = """
Use plain text only. No markdown headers, no bold, no bullet symbols, no special formatting.
Use numbered sections with a colon, like:
1. Risk Summary: [your text here]
2. Recommended Action: [your text here]
Keep each section on its own line."""

def generate_triage_summary(cve_id, description, cvss_score):
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=500,
        messages=[{"role": "user", "content": f"""You are a security analyst assistant. Analyze this vulnerability.

CVE ID: {cve_id}
CVSS Score: {cvss_score}
Description: {description}

Provide these four sections:
1. Risk Summary (1-2 sentences)
2. Recommended Action (Respond Now / Escalate / Monitor / Defer)
3. Rationale (1-2 sentences)
4. Confidence Score (High / Medium / Low)
{PLAIN_TEXT_INSTRUCTION}"""}]
    )
    return message.content[0].text

def generate_url_analysis(url, threat_type, severity):
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=500,
        messages=[{"role": "user", "content": f"""You are a security analyst reviewing a malicious URL indicator.

URL: {url}
Threat Type: {threat_type}
Severity: {severity}

Provide these five sections:
1. Threat Summary (1-2 sentences)
2. Recommended Action (Block Immediately / Investigate / Monitor)
3. Affected Systems (what enterprise assets are most at risk)
4. Mitigation Steps (2-3 specific actions, listed as plain text)
5. Confidence Score (High / Medium / Low)
{PLAIN_TEXT_INSTRUCTION}"""}]
    )
    return message.content[0].text

def generate_phishing_summary(email_text):
    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=500,
        messages=[{"role": "user", "content": f"""You are a security analyst reviewing a potential phishing email.

Email Content:
{email_text[:500]}

Provide these five sections:
1. Threat Assessment (1-2 sentences)
2. Risk Level (Critical / High / Medium / Low)
3. Recommended Action (Block & Quarantine / Escalate to SOC / Flag for Review / Monitor)
4. Key Indicators (2-3 specific phishing signals, listed as plain text)
5. Confidence Score (High / Medium / Low)
{PLAIN_TEXT_INSTRUCTION}"""}]
    )
    return message.content[0].text

def show_ai_summary(text):
    """Display AI summary in a clean styled box."""
    st.markdown(f'<div class="triage-box">{text}</div>', unsafe_allow_html=True)

def log_decision(source, id_val, severity, ai_rec, human_dec, rationale):
    st.session_state.audit_log.append({
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Source": source,
        "ID": id_val,
        "Severity": severity,
        "AI Recommendation": ai_rec,
        "Human Decision": human_dec,
        "Rationale": rationale,
        "Actioned By": "Analyst"
    })

# ── TABS ──────────────────────────────────────────────────────────────────────

st.markdown(
    "<p style='color:#a8b2d8; font-size:0.9rem; margin-bottom:0.5rem;'>"
    "👆 Use the tabs below to triage threats by category</p>",
    unsafe_allow_html=True
)

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview",
    "🔴 CVE Triage",
    "🌐 URL Indicators",
    "📧 Phishing",
    "📋 Audit Log"
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════

with tab1:

    insight = (f"{pending} threats pending analyst review across "
               f"{len(df) if not df.empty else 0} critical CVEs, "
               f"{len(indicators_df) if not indicators_df.empty else 0} active URL indicators, and "
               f"{len(phishing_df) if not phishing_df.empty else 0} phishing emails. "
               f"{critical_url} critical URL indicators require immediate attention. "
               f"{len(st.session_state.audit_log)} decisions logged this session.")

    st.markdown(f"""
    <div class="insight-box">
        <div class="insight-title">🤖 AI Environment Summary</div>
        <div class="insight-text">{insight}</div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Critical CVEs", len(df) if not df.empty else 0)
    with col2:
        st.metric("URL Indicators", len(indicators_df) if not indicators_df.empty else 0,
                  delta=f"{critical_url} critical", delta_color="inverse")
    with col3:
        st.metric("Phishing Emails", len(phishing_df) if not phishing_df.empty else 0)
    with col4:
        st.metric("Escalated", st.session_state.escalated_count)
    with col5:
        st.metric("Resolved Today", st.session_state.resolved_count)

    st.divider()

    st.markdown('<div class="section-header">📊 Threat Landscape Summary</div>',
                unsafe_allow_html=True)

    summary_data = {
        "Threat Source": [
            "🔴 Critical CVEs (NIST NVD)",
            "🌐 URL Threat Indicators",
            "📧 Phishing Emails"
        ],
        "Count": [
            len(df) if not df.empty else 0,
            len(indicators_df) if not indicators_df.empty else 0,
            len(phishing_df) if not phishing_df.empty else 0
        ],
        "Severity": [
            "All CVSS 9.8 — Critical",
            f"{critical_url} Critical · {high_url} High · 1 Medium",
            "Labeled phishing — pending analyst scoring"
        ],
        "Triage Tab": [
            "🔴 CVE Triage",
            "🌐 URL Indicators",
            "📧 Phishing"
        ],
        "Status": ["Pending Review", "Pending Review", "Pending Review"]
    }

    st.dataframe(pd.DataFrame(summary_data), use_container_width=True, hide_index=True)

    st.divider()

    st.markdown('<div class="section-header">🏛️ Governance Architecture</div>',
                unsafe_allow_html=True)

    g_col1, g_col2, g_col3, g_col4 = st.columns(4)
    with g_col1:
        st.markdown("**1. Ingest**")
        st.caption("Live threat data from NIST NVD, phishing dataset, and URL intelligence feed")
    with g_col2:
        st.markdown("**2. AI Reasons**")
        st.caption("Claude analyzes each threat and generates a triage summary with confidence score")
    with g_col3:
        st.markdown("**3. Human Decides**")
        st.caption("Analyst approves, escalates, or overrides — nothing executes without human approval")
    with g_col4:
        st.markdown("**4. System Logs**")
        st.caption("Every decision is logged with timestamp, AI recommendation, human decision, and rationale")

    st.markdown("""
    <div class="governance-note">
        ⚙️ <strong>Design principle:</strong> AI recommends. Humans decide. Everything is logged.
        Override tracking identifies where AI and analyst judgment diverge —
        enabling continuous improvement without retraining.
        Built by Kenneth R. Turner · <a href="https://kenturnerportfolio.com/products.html"
        style="color:#7eb8f7;">kenturnerportfolio.com</a>
    </div>
    """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — CVE TRIAGE
# ══════════════════════════════════════════════════════════════════════════════

with tab2:
    st.markdown('<div class="section-header">🔴 Critical Vulnerabilities — Pending Triage</div>',
                unsafe_allow_html=True)

    st.markdown("""
    <div class="governance-note">
        Data source: NIST National Vulnerability Database (NVD) · Remote code execution vulnerabilities ·
        CVSS 9.0+ · AI generates triage summary · Analyst approves action before routing ·
        In production, AI summaries would be pre-generated on ingestion — analysts review a pre-triaged queue.
    </div>
    """, unsafe_allow_html=True)

    if not df.empty:
        st.caption(f"{len(df)} critical CVEs loaded · Sorted by most recent publication")

        for idx, row in df.iterrows():
            with st.expander(
                f"🔴 {row['CVE ID']} — CVSS {row['CVSS Score']} — Published {row['Published']}"
            ):
                st.markdown(f"**Description:** {row['Description']}")

                if st.button("🤖 Generate AI Triage Summary", key=f"triage_{idx}"):
                    with st.spinner("Analyzing vulnerability..."):
                        st.session_state[f"summary_{idx}"] = generate_triage_summary(
                            row['CVE ID'], row['Description'], row['CVSS Score'])

                if f"summary_{idx}" in st.session_state:
                    st.markdown("---")
                    show_ai_summary(st.session_state[f"summary_{idx}"])
                    st.markdown("**👤 Human Review Required — Select Action:**")
                    col_a, col_b, col_c = st.columns(3)

                    with col_a:
                        if st.button("✅ Approve & Route", key=f"approve_{idx}"):
                            st.success(f"✅ {row['CVE ID']} routed to response queue.")
                            log_decision("CVE Feed", row['CVE ID'], row['CVSS Score'],
                                        "Approve & Route", "Approved & Routed",
                                        "Analyst approved AI recommendation")
                            st.session_state.resolved_count += 1

                    with col_b:
                        if st.button("⚠️ Escalate", key=f"escalate_{idx}"):
                            st.warning(f"⚠️ {row['CVE ID']} escalated to senior analyst.")
                            log_decision("CVE Feed", row['CVE ID'], row['CVSS Score'],
                                        "Escalate", "Escalated",
                                        "Analyst escalated to senior review")
                            st.session_state.escalated_count += 1

                    with col_c:
                        override_reason = st.text_input(
                            "Override reason (required):",
                            key=f"override_reason_{idx}",
                            placeholder="Why are you deferring this CVE?")
                        if st.button("🔁 Override & Defer", key=f"defer_{idx}"):
                            if override_reason:
                                st.info(f"🔁 {row['CVE ID']} deferred. Override logged.")
                                log_decision("CVE Feed", row['CVE ID'], row['CVSS Score'],
                                            "Defer", "Override & Deferred", override_reason)
                            else:
                                st.error("Override reason is required before deferring.")
    else:
        st.warning("No CVE data loaded. Check your connection to NIST NVD.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — URL INDICATORS
# ══════════════════════════════════════════════════════════════════════════════

with tab3:
    st.markdown('<div class="section-header">🌐 Active Threat Indicators — URL Intelligence Feed</div>',
                unsafe_allow_html=True)

    st.markdown("""
    <div class="governance-note">
        Data source: Active malicious URL indicator feed ·
        Phishing, malware distribution, ransomware, credential harvesting, account takeover ·
        AI generates threat analysis · Analyst approves block or investigation action
    </div>
    """, unsafe_allow_html=True)

    if not indicators_df.empty:
        col_i1, col_i2, col_i3 = st.columns(3)
        with col_i1:
            st.metric("Total Indicators", len(indicators_df))
        with col_i2:
            st.metric("Critical", critical_url)
        with col_i3:
            st.metric("High", high_url)

        st.divider()

        for idx, row in indicators_df.iterrows():
            severity_icon = ("🔴" if row['severity'] == "Critical"
                            else "🟠" if row['severity'] == "High" else "🟡")
            with st.expander(
                f"{severity_icon} {row['type']} — {row['url']} — Reported {row['reported']}"
            ):
                col_left, col_right = st.columns(2)
                with col_left:
                    st.markdown(f"**URL:** `{row['url']}`")
                    st.markdown(f"**Threat Type:** {row['type']}")
                with col_right:
                    st.markdown(f"**Severity:** {row['severity']}")
                    st.markdown(f"**Reported:** {row['reported']}")

                if st.button("🤖 Generate Threat Analysis", key=f"url_{idx}"):
                    with st.spinner("Analyzing threat indicator..."):
                        st.session_state[f"url_analysis_{idx}"] = generate_url_analysis(
                            row['url'], row['type'], row['severity'])

                if f"url_analysis_{idx}" in st.session_state:
                    st.markdown("---")
                    show_ai_summary(st.session_state[f"url_analysis_{idx}"])
                    st.markdown("**👤 Analyst Decision Required:**")
                    col_a, col_b, col_c = st.columns(3)

                    with col_a:
                        if st.button("🚫 Block Immediately", key=f"url_block_{idx}"):
                            st.error(f"🚫 {row['url']} blocked.")
                            log_decision("URL Feed", f"URL-{idx+1}", row['severity'],
                                        "Block Immediately", "Blocked",
                                        f"Analyst blocked {row['type']} indicator")
                            st.session_state.resolved_count += 1

                    with col_b:
                        if st.button("🔍 Investigate", key=f"url_investigate_{idx}"):
                            st.warning(f"🔍 {row['url']} flagged for investigation.")
                            log_decision("URL Feed", f"URL-{idx+1}", row['severity'],
                                        "Investigate", "Under Investigation",
                                        "Analyst initiated investigation")
                            st.session_state.escalated_count += 1

                    with col_c:
                        url_override = st.text_input(
                            "Override reason (required):",
                            key=f"url_override_{idx}",
                            placeholder="Why is this a false positive?")
                        if st.button("✅ False Positive", key=f"url_fp_{idx}"):
                            if url_override:
                                st.success(f"✅ {row['url']} marked as false positive.")
                                log_decision("URL Feed", f"URL-{idx+1}", row['severity'],
                                            "Block Immediately", "False Positive", url_override)
                            else:
                                st.error("Override reason required before marking as false positive.")
    else:
        st.warning("No threat indicators loaded. Check data/threat_indicators.json.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — PHISHING
# ══════════════════════════════════════════════════════════════════════════════

with tab4:
    st.markdown('<div class="section-header">📧 Phishing Email Triage — AI-Assisted Analysis</div>',
                unsafe_allow_html=True)

    st.markdown("""
    <div class="governance-note">
        Data source: Labeled phishing email dataset (82,500 emails) ·
        AI analyzes email content for phishing indicators and risk level ·
        Analyst confirms block, escalates to SOC, or overrides with written rationale
    </div>
    """, unsafe_allow_html=True)

    if not phishing_df.empty:
        st.caption(f"{len(phishing_df)} phishing emails loaded for analyst review")

        for idx, row in phishing_df.iterrows():
            email_preview = str(row['text_combined'])[:120] + "..."
            with st.expander(f"📧 Email #{idx + 1} — {email_preview}"):
                st.markdown("**Email Content Preview:**")
                st.text(str(row['text_combined'])[:400])

                if st.button("🤖 Generate Phishing Analysis", key=f"phishing_{idx}"):
                    with st.spinner("Analyzing email for phishing indicators..."):
                        st.session_state[f"phishing_summary_{idx}"] = generate_phishing_summary(
                            str(row['text_combined']))

                if f"phishing_summary_{idx}" in st.session_state:
                    st.markdown("---")
                    show_ai_summary(st.session_state[f"phishing_summary_{idx}"])
                    st.markdown("**👤 Analyst Decision Required:**")
                    col_a, col_b, col_c = st.columns(3)

                    with col_a:
                        if st.button("🚫 Block & Quarantine", key=f"block_{idx}"):
                            st.error(f"🚫 Email #{idx + 1} blocked and quarantined.")
                            log_decision("Phishing Feed", f"PHISH-{idx+1}", "High",
                                        "Block & Quarantine", "Blocked & Quarantined",
                                        "Analyst confirmed phishing — blocked")
                            st.session_state.resolved_count += 1

                    with col_b:
                        if st.button("⚠️ Escalate to SOC", key=f"phish_escalate_{idx}"):
                            st.warning(f"⚠️ Email #{idx + 1} escalated to SOC.")
                            log_decision("Phishing Feed", f"PHISH-{idx+1}", "High",
                                        "Escalate to SOC", "Escalated to SOC",
                                        "Analyst escalated for deeper investigation")
                            st.session_state.escalated_count += 1

                    with col_c:
                        phish_override = st.text_input(
                            "Override reason (required):",
                            key=f"phish_override_{idx}",
                            placeholder="Why are you releasing this email?")
                        if st.button("✅ Release — False Positive", key=f"release_{idx}"):
                            if phish_override:
                                st.success(f"✅ Email #{idx + 1} released. Override logged.")
                                log_decision("Phishing Feed", f"PHISH-{idx+1}", "High",
                                            "Block & Quarantine", "Released — False Positive",
                                            phish_override)
                            else:
                                st.error("Override reason required before releasing.")
    else:
        st.warning("No phishing data loaded. Check data/phishing_sample.csv.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════

with tab5:
    st.markdown('<div class="section-header">📋 Audit Log — All Decisions This Session</div>',
                unsafe_allow_html=True)

    st.markdown("""
    <div class="governance-note">
        Every analyst decision is logged — approval, escalation, or override.
        Override tracking surfaces where AI and analyst judgment diverge,
        enabling model quality improvement over time without retraining.
        Download the full log as CSV for compliance reporting.
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.audit_log:
        audit_df = pd.DataFrame(st.session_state.audit_log)
        decisions = audit_df['Human Decision'].value_counts()

        d_col1, d_col2, d_col3, d_col4 = st.columns(4)
        with d_col1:
            st.metric("Total Decisions", len(audit_df))
        with d_col2:
            st.metric("Approved & Routed", decisions.get("Approved & Routed", 0))
        with d_col3:
            escalated = (decisions.get("Escalated", 0) +
                        decisions.get("Escalated to SOC", 0) +
                        decisions.get("Under Investigation", 0))
            st.metric("Escalated / Investigating", escalated)
        with d_col4:
            overrides = sum(1 for d in audit_df['Human Decision']
                           if any(x in str(d) for x in
                                  ['Override', 'False Positive', 'Released']))
            st.metric("Analyst Overrides", overrides)

        st.divider()
        st.dataframe(audit_df, use_container_width=True)

        csv = audit_df.to_csv(index=False)
        st.download_button(
            label="⬇️ Download Audit Log (CSV)",
            data=csv,
            file_name=f"audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

        if overrides > 0:
            st.divider()
            st.markdown("**🔍 Override Analysis — Where AI and Analyst Disagreed:**")
            override_df = audit_df[audit_df['Human Decision'].str.contains(
                'Override|False Positive|Released', na=False)]
            if not override_df.empty:
                st.dataframe(override_df[['Timestamp', 'Source', 'ID',
                                          'AI Recommendation', 'Human Decision', 'Rationale']],
                            use_container_width=True)
    else:
        st.info("No decisions logged yet. Triage a threat in the CVE, URL, or Phishing tabs to begin.")
        st.markdown("""
        **How the audit log works:**
        - Every approval, escalation, and override is captured automatically
        - Override decisions require written analyst rationale
        - The log persists for the duration of the session
        - Download as CSV for compliance reporting or analysis
        """)

# ── FOOTER ────────────────────────────────────────────────────────────────────

st.markdown("---")
st.caption(
    "AI Security Triage Dashboard · Kenneth R. Turner · kenturnerportfolio.com · "
    "Governance: AI recommends, human decides, system logs everything · "
    "Built with Python, Streamlit, Anthropic Claude API, NIST NVD"
)