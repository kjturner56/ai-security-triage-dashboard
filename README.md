# AI Security Triage Dashboard

A governed AI decision-support tool that helps security analysts triage CVE vulnerabilities, phishing emails, and active URL threat indicators. Built to demonstrate enterprise AI governance architecture applied to a cybersecurity context.

## What It Does

- Pulls live critical CVEs from the NIST NVD API (CVSS 9.0+, last 90 days)
- Cross-references each CVE against the CISA Known Exploited Vulnerabilities catalog to surface active exploitation status
- Analyzes phishing email content and URL threat indicators using the Claude API
- Requires analyst approval before any action executes
- Logs every decision with timestamp, AI recommendation, human decision, and override rationale
- Exports full audit log as CSV for compliance reporting

## Governance Architecture

AI recommends. Humans decide. Everything is logged.

Override tracking identifies where AI and analyst judgment diverge — enabling continuous improvement without retraining. No action executes without analyst approval.

## Stack

Python · Streamlit · Anthropic Claude API · NIST NVD API · CISA KEV · GitHub · Streamlit Community Cloud

## Live App

[ai-security-triage-dashboard.streamlit.app](https://ai-security-triage-dashboard.streamlit.app)
