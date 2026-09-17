import streamlit as st
import tempfile

from log_parser import parse_logs
from threat_analyzer import analyze_threats
from risk_scoring import calculate_risk

st.set_page_config(page_title="Insider Threat Detection Dashboard", layout="wide")

st.title("🔐 Insider Threat Log Analyzer")
st.write("Upload a Linux authentication log file to analyze insider threats.")

uploaded_file = st.file_uploader("Upload auth.log file", type=["log", "txt"])

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        log_path = tmp.name

    with open(log_path, "r") as f:
        logs = f.readlines()

    events = parse_logs(logs)
    threats = analyze_threats(events)
    risks = calculate_risk(threats)

    st.subheader("🚨 Suspicious Users")
    if threats:
        for user, issues in threats.items():
            st.markdown(f"**{user}**")
            for issue in issues:
                st.write(f"- {issue}")
    else:
        st.success("No suspicious activity detected.")

    st.subheader("📊 Risk Scores")
    risk_table = []
    for user, score in risks.items():
        risk_table.append({
            "User": user,
            "Risk Score": score
        })
    st.table(risk_table)

    st.subheader("⏱️ Timeline of Events")
    timeline = []
    for e in events:
        if e["event"] != "Other":
            timeline.append({
                "Timestamp": e["timestamp"],
                "User": e["user"],
                "Event": e["event"]
            })
    st.table(timeline)

    st.subheader("⬇️ Export Results")
    st.download_button(
        label="Download Risk Report (CSV)",
        data=str(risk_table),
        file_name="risk_report.csv"
    )
