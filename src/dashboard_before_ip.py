import streamlit as st
import tempfile

from log_parser import parse_logs
from threat_analyzer import analyze_threats
from risk_scoring import calculate_risk
from database import save_analysis, get_threat_history


st.set_page_config(
    page_title="Insider Threat Detection Dashboard",
    layout="wide"
)


# -------------------------------------------------
# Risk Level Function
# -------------------------------------------------

def get_risk_level(score):
    """
    Convert numerical risk score into
    an easy-to-understand risk level.
    """

    if score <= 30:
        return "Low"

    elif score <= 50:
        return "Medium"

    elif score <= 70:
        return "High"

    else:
        return "Critical"


# -------------------------------------------------
# Dashboard Header
# -------------------------------------------------

st.title("🔐 Insider Threat Log Analyzer")

st.write(
    "Upload a Linux authentication log file "
    "to analyze insider threats."
)

uploaded_file = st.file_uploader(
    "Upload auth.log file",
    type=["log", "txt"]
)


if uploaded_file is not None:

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        log_path = tmp.name

    with open(log_path, "r") as f:
        logs = f.readlines()

    # -------------------------------------------------
    # Parse Logs
    # -------------------------------------------------

    events = parse_logs(logs)

    # -------------------------------------------------
    # Threat Detection
    # -------------------------------------------------

    threats = analyze_threats(events)

    # -------------------------------------------------
    # Risk Scoring
    # -------------------------------------------------

    risks = calculate_risk(threats)

    # -------------------------------------------------
    # Dashboard Summary Cards
    # -------------------------------------------------

    total_events = len(
        [
            event
            for event in events
            if event["event"] != "Other"
        ]
    )

    suspicious_users = len(threats)

    total_alerts = sum(
        len(issues)
        for issues in threats.values()
    )

    highest_risk = (
        max(risks.values())
        if risks
        else 0
    )

    highest_risk_level = get_risk_level(
        highest_risk
    )

    st.subheader("📌 Analysis Summary")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Events",
            total_events
        )

    with col2:
        st.metric(
            "Suspicious Users",
            suspicious_users
        )

    with col3:
        st.metric(
            "Total Alerts",
            total_alerts
        )

    with col4:
        st.metric(
            "Highest Risk",
            f"{highest_risk} ({highest_risk_level})"
        )

    # -------------------------------------------------
    # Save Analysis to SQLite
    # -------------------------------------------------

    if st.button("💾 Save Analysis to Database"):

        if threats:

            save_analysis(
                threats,
                risks
            )

            st.success(
                "Analysis saved successfully "
                "to SQLite database."
            )

        else:

            st.warning(
                "No suspicious activity available to save."
            )

    # -------------------------------------------------
    # Explainable Threat Alerts
    # -------------------------------------------------

    st.subheader(
        "🚨 Suspicious Users & Alert Explanations"
    )

    if threats:

        for user, issues in threats.items():

            score = risks.get(user, 0)

            level = get_risk_level(score)

            st.markdown(
                f"### 👤 {user}"
            )

            st.write(
                f"**Risk Score:** {score}/100 "
                f"| **Risk Level:** {level}"
            )

            for issue in issues:

                st.info(issue)

    else:

        st.success(
            "No suspicious activity detected."
        )

    # -------------------------------------------------
    # Risk Scores and Risk Levels
    # -------------------------------------------------

    st.subheader(
        "📊 Risk Assessment"
    )

    risk_table = []

    for user, score in risks.items():

        risk_table.append(
            {
                "User": user,
                "Risk Score": score,
                "Risk Level": get_risk_level(score)
            }
        )

    st.table(
        risk_table
    )

    # -------------------------------------------------
    # Timeline of Events
    # -------------------------------------------------

    st.subheader(
        "⏱️ Timeline of Events"
    )

    timeline = []

    for event in events:

        if event["event"] != "Other":

            timeline.append(
                {
                    "Timestamp": event["timestamp"],
                    "User": event["user"],
                    "Event": event["event"]
                }
            )

    st.table(
        timeline
    )

    # -------------------------------------------------
    # Export Results
    # -------------------------------------------------

    st.subheader(
        "⬇️ Export Results"
    )

    st.download_button(
        label="Download Risk Report (CSV)",
        data=str(risk_table),
        file_name="risk_report.csv"
    )

    # -------------------------------------------------
    # Historical Threat Analysis
    # -------------------------------------------------

    st.subheader(
        "🗄️ Historical Threat Analysis"
    )

    history = get_threat_history()

    if history:

        history_table = []

        for record in history:

            stored_score = record[3]

            history_table.append(
                {
                    "Analysis Time": record[0],
                    "User": record[1],
                    "Threat Explanation": record[2],
                    "Risk Score": stored_score,
                    "Risk Level": get_risk_level(
                        stored_score
                    )
                }
            )

        st.dataframe(
            history_table,
            use_container_width=True
        )

    else:

        st.info(
            "No historical threat records stored yet."
        )
