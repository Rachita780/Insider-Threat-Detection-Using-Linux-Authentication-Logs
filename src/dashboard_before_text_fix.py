import streamlit as st
import tempfile
import pandas as pd

from log_parser import parse_logs
from threat_analyzer import analyze_threats
from risk_scoring import calculate_risk
from database import save_analysis, get_threat_history


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Insider Threat Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# SAFE CUSTOM STYLING
# =========================================================

st.markdown(
    """
    <style>

    .stApp {
        background-color: #f7f9fc;
    }

    .block-container {
        padding-top: 1.4rem;
        padding-bottom: 3rem;
        max-width: 1450px;
    }

    section[data-testid="stSidebar"] {
        background-color: #12345b;
    }

    section[data-testid="stSidebar"] p,
    section[data-testid="stSidebar"] span,
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] div {
        color: white;
    }

    div[data-testid="stMetric"] {
        background: white;
        border: 1px solid #dce6f2;
        border-radius: 14px;
        padding: 18px;
        box-shadow: 0 4px 12px rgba(40, 70, 110, 0.08);
    }

    div[data-testid="stMetricLabel"] {
        font-weight: 700;
    }

    div[data-testid="stMetricValue"] {
        font-size: 30px;
        font-weight: 800;
        color: #173b68;
    }

    div[data-testid="stFileUploader"] {
        background: white;
        border-radius: 12px;
        padding: 10px;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
    }

    .stButton > button {
        background-color: #2563eb;
        color: white;
        border-radius: 8px;
        border: none;
        font-weight: 700;
    }

    .stButton > button:hover {
        background-color: #1d4ed8;
        color: white;
    }

    .stDownloadButton > button {
        background-color: #0f766e;
        color: white;
        border-radius: 8px;
        border: none;
        font-weight: 700;
    }

    h1 {
        color: #16345d;
    }

    h2,
    h3 {
        color: #1f4777;
    }

    hr {
        border-color: #dce6f2;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def get_risk_level(score):
    if score <= 30:
        return "Low"

    elif score <= 50:
        return "Medium"

    elif score <= 70:
        return "High"

    else:
        return "Critical"


def get_risk_icon(level):
    if level == "Low":
        return "🟢"

    elif level == "Medium":
        return "🟠"

    elif level == "High":
        return "🔴"

    else:
        return "🚨"


def get_threat_type(issue):
    if "Brute-force" in issue:
        return "Brute-force"

    elif "Odd-hour" in issue:
        return "Odd-hour Login"

    elif "sudo" in issue:
        return "Excessive Sudo Usage"

    else:
        return "Other"


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.title("🛡️ Security Console")

    st.write(
        "**Insider Threat Detection**"
    )

    st.caption(
        "Linux Authentication Log Analyzer"
    )

    st.divider()

    st.subheader("🔎 Detection Rules")

    st.write("🔐 Brute-force attempts")
    st.write("🌙 Odd-hour logins")
    st.write("🔑 Excessive sudo usage")

    st.divider()

    st.subheader("⚙️ Enhanced Features")

    st.write("✅ Configurable thresholds")
    st.write("✅ Time-window detection")
    st.write("✅ User working profiles")
    st.write("✅ Explainable alerts")
    st.write("✅ Source IP extraction")
    st.write("✅ Historical analysis")

    st.divider()

    st.caption(
        "Cybersecurity Analytics Dashboard"
    )


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ Insider Threat Detection")

st.markdown(
    "### Linux Authentication Security Analytics Dashboard"
)

st.caption(
    "Analyse Linux authentication logs, detect suspicious activity, "
    "calculate risk scores and review historical alerts."
)

st.divider()


# =========================================================
# FILE UPLOAD
# =========================================================

st.subheader("📂 Authentication Log Analysis")

st.write(
    "Upload a Linux authentication log file to begin security analysis."
)

uploaded_file = st.file_uploader(
    "Upload auth.log or text log file",
    type=["log", "txt"]
)


# =========================================================
# ANALYSIS
# =========================================================

if uploaded_file is not None:

    with tempfile.NamedTemporaryFile(
        delete=False
    ) as tmp:

        tmp.write(
            uploaded_file.read()
        )

        log_path = tmp.name

    with open(
        log_path,
        "r"
    ) as f:

        logs = f.readlines()

    # Parse Logs
    events = parse_logs(
        logs
    )

    # Detect Threats
    threats = analyze_threats(
        events
    )

    # Calculate Risk
    risks = calculate_risk(
        threats
    )


    # =====================================================
    # SUMMARY
    # =====================================================

    total_events = len(
        [
            event
            for event in events
            if event["event"] != "Other"
        ]
    )

    suspicious_users = len(
        threats
    )

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

    st.subheader("📌 Security Overview")

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            label="🔍 Total Events",
            value=total_events
        )

    with col2:

        st.metric(
            label="👥 Suspicious Users",
            value=suspicious_users
        )

    with col3:

        st.metric(
            label="🚨 Total Alerts",
            value=total_alerts
        )

    with col4:

        st.metric(
            label="🛡️ Highest Risk",
            value=highest_risk,
            delta=highest_risk_level,
            delta_color="off"
        )


    # =====================================================
    # DATABASE SAVE
    # =====================================================

    st.write("")

    if st.button(
        "💾 Save Analysis to Database"
    ):

        if threats:

            save_analysis(
                threats,
                risks
            )

            st.success(
                "Analysis saved successfully to SQLite database."
            )

        else:

            st.warning(
                "No suspicious activity available to save."
            )


    # =====================================================
    # ALERT EXPLANATIONS
    # =====================================================

    st.divider()

    st.subheader(
        "🚨 Suspicious Users & Alert Explanations"
    )

    if threats:

        for user, issues in threats.items():

            score = risks.get(
                user,
                0
            )

            level = get_risk_level(
                score
            )

            risk_icon = get_risk_icon(
                level
            )

            with st.container(
                border=True
            ):

                user_col, risk_col = st.columns(
                    [3, 1]
                )

                with user_col:

                    st.markdown(
                        f"### 👤 {user}"
                    )

                with risk_col:

                    st.markdown(
                        f"### {risk_icon} {level}"
                    )

                st.write(
                    f"**Risk Score:** {score}/100"
                )

                for issue in issues:

                    if "Brute-force" in issue:

                        st.error(
                            f"🔐 {issue}"
                        )

                    elif "Odd-hour" in issue:

                        st.warning(
                            f"🌙 {issue}"
                        )

                    elif "sudo" in issue:

                        st.warning(
                            f"🔑 {issue}"
                        )

                    else:

                        st.info(
                            issue
                        )

    else:

        st.success(
            "✅ No suspicious activity detected."
        )


    # =====================================================
    # RISK + THREAT DISTRIBUTION
    # =====================================================

    st.divider()

    left_column, right_column = st.columns(
        [1, 1]
    )


    # -----------------------------------------------------
    # Risk Assessment
    # -----------------------------------------------------

    with left_column:

        st.subheader(
            "📊 Risk Assessment"
        )

        risk_table = []

        for user, score in risks.items():

            level = get_risk_level(
                score
            )

            risk_table.append(
                {
                    "User": user,
                    "Risk Score": score,
                    "Risk Level":
                        f"{get_risk_icon(level)} {level}"
                }
            )

        if risk_table:

            risk_df = pd.DataFrame(
                risk_table
            )

            st.dataframe(
                risk_df,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.info(
                "No risk scores available."
            )


    # -----------------------------------------------------
    # Threat Distribution
    # -----------------------------------------------------

    with right_column:

        st.subheader(
            "📈 Threat Distribution"
        )

        threat_distribution = {
            "Brute-force": 0,
            "Odd-hour Login": 0,
            "Excessive Sudo Usage": 0
        }

        for user, issues in threats.items():

            for issue in issues:

                threat_type = get_threat_type(
                    issue
                )

                if (
                    threat_type
                    in threat_distribution
                ):

                    threat_distribution[
                        threat_type
                    ] += 1

        chart_data = pd.DataFrame(
            {
                "Threat Type":
                    list(
                        threat_distribution.keys()
                    ),

                "Alerts":
                    list(
                        threat_distribution.values()
                    )
            }
        )

        chart_data = chart_data[
            chart_data["Alerts"] > 0
        ]

        if not chart_data.empty:

            st.bar_chart(
                chart_data.set_index(
                    "Threat Type"
                )
            )

            st.caption(
                "Number of alerts generated for each threat category."
            )

        else:

            st.info(
                "No threat distribution available."
            )


    # =====================================================
    # EVENT TIMELINE
    # =====================================================

    st.divider()

    st.subheader(
        "🌐 Authentication Event Timeline"
    )

    timeline = []

    for event in events:

        if event["event"] != "Other":

            timeline.append(
                {
                    "Timestamp":
                        event["timestamp"],

                    "User":
                        event["user"],

                    "Source IP":
                        event.get(
                            "source_ip",
                            "N/A"
                        ),

                    "Event":
                        event["event"]
                }
            )

    if timeline:

        timeline_df = pd.DataFrame(
            timeline
        )

        st.dataframe(
            timeline_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No authentication events available for the timeline."
        )


    # =====================================================
    # EXPORT
    # =====================================================

    st.divider()

    st.subheader(
        "⬇️ Export Security Results"
    )

    if risk_table:

        csv_data = pd.DataFrame(
            risk_table
        ).to_csv(
            index=False
        )

    else:

        csv_data = (
            "User,Risk Score,Risk Level\n"
        )

    st.download_button(
        label="📥 Download Risk Report (CSV)",
        data=csv_data,
        file_name="risk_report.csv",
        mime="text/csv"
    )


    # =====================================================
    # HISTORICAL THREAT ANALYSIS
    # =====================================================

    st.divider()

    st.subheader(
        "🗄️ Historical Threat Analysis"
    )

    history = get_threat_history()

    if history:

        history_table = []

        for record in history:

            stored_score = record[3]

            stored_level = get_risk_level(
                stored_score
            )

            history_table.append(
                {
                    "Analysis Time":
                        record[0],

                    "User":
                        record[1],

                    "Threat Explanation":
                        record[2],

                    "Risk Score":
                        stored_score,

                    "Risk Level":
                        f"{get_risk_icon(stored_level)} "
                        f"{stored_level}"
                }
            )

        history_df = pd.DataFrame(
            history_table
        )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No historical threat records stored yet."
        )


# =========================================================
# EMPTY STATE
# =========================================================

else:

    st.info(
        "🔎 Upload a Linux authentication log file above "
        "to begin insider-threat analysis."
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        with st.container(
            border=True
        ):

            st.subheader(
                "🔐 Brute-force"
            )

            st.write(
                "Detects rapid repeated failed "
                "authentication attempts."
            )

    with col2:

        with st.container(
            border=True
        ):

            st.subheader(
                "🌙 Odd-hour Login"
            )

            st.write(
                "Checks logins against configured "
                "user working hours."
            )

    with col3:

        with st.container(
            border=True
        ):

            st.subheader(
                "🔑 Privilege Usage"
            )

            st.write(
                "Identifies excessive sudo activity "
                "using configured thresholds."
            )
