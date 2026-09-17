import streamlit as st
import tempfile
import pandas as pd
import os
import json

from log_parser import parse_logs

from threat_analyzer import (
    analyze_threats,
    load_config,
    load_user_profiles,
    load_behavior_baseline
)

from risk_scoring import calculate_risk

from database import (
    save_analysis,
    get_threat_history
)


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Insider Threat Detection Dashboard",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# CUSTOM DASHBOARD STYLING
# =========================================================

st.markdown(
    """
<style>

/* -------------------------------------------------------
   MAIN APPLICATION
------------------------------------------------------- */

.stApp {
    background-color: #F4F7FB;
}

/* Main dashboard content */

.main .block-container {
    padding-top: 1.5rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}


/* -------------------------------------------------------
   MAIN PAGE TEXT
------------------------------------------------------- */

.main p {
    color: #334155;
}

.main label {
    color: #334155 !important;
}

.main h1 {
    color: #12345B !important;
    font-weight: 800 !important;
}

.main h2 {
    color: #173F6D !important;
    font-weight: 750 !important;
}

.main h3 {
    color: #24568A !important;
    font-weight: 700 !important;
}

.main [data-testid="stCaptionContainer"] p {
    color: #64748B !important;
}


/* -------------------------------------------------------
   SIDEBAR
------------------------------------------------------- */

section[data-testid="stSidebar"] {
    background: linear-gradient(
        180deg,
        #12345B 0%,
        #184A7A 100%
    );
}

section[data-testid="stSidebar"] h1 {
    color: #FFFFFF !important;
}

section[data-testid="stSidebar"] h2 {
    color: #FFFFFF !important;
}

section[data-testid="stSidebar"] h3 {
    color: #FFFFFF !important;
}

section[data-testid="stSidebar"] p {
    color: #FFFFFF !important;
}

section[data-testid="stSidebar"]
[data-testid="stCaptionContainer"] p {
    color: #BFD1E5 !important;
}

section[data-testid="stSidebar"] hr {
    border-color: rgba(255,255,255,0.22);
}


/* -------------------------------------------------------
   FILE UPLOADER
------------------------------------------------------- */

.main [data-testid="stFileUploader"] {
    background-color: #FFFFFF;
    border: 1px solid #D9E4F0;
    border-radius: 14px;
    padding: 10px;
}

.main [data-testid="stFileUploaderDropzone"] {
    background-color: #EDF4FC !important;
    border: 2px dashed #8DB5DE !important;
    border-radius: 12px !important;
}

.main [data-testid="stFileUploaderDropzone"] p {
    color: #334155 !important;
}

.main [data-testid="stFileUploaderDropzone"] span {
    color: #334155 !important;
}

.main [data-testid="stFileUploaderDropzone"] small {
    color: #64748B !important;
}

.main [data-testid="stFileUploaderDropzone"] button {
    background-color: #2563EB !important;
    color: #FFFFFF !important;
    border: none !important;
    border-radius: 8px !important;
}


/* -------------------------------------------------------
   METRIC CARDS
------------------------------------------------------- */

.main div[data-testid="stMetric"] {
    background-color: #FFFFFF;

    border: 1px solid #D8E4F0;
    border-radius: 16px;

    padding: 20px;

    box-shadow:
        0 5px 15px rgba(31, 65, 105, 0.08);
}

.main div[data-testid="stMetricLabel"] p {
    color: #64748B !important;
    font-weight: 700 !important;
}

.main div[data-testid="stMetricValue"] {
    color: #173F6D !important;
    font-size: 30px !important;
    font-weight: 800 !important;
}

.main div[data-testid="stMetricDelta"] {
    color: #B45309 !important;
    font-weight: 700 !important;
}


/* -------------------------------------------------------
   BORDERED USER CONTAINERS
------------------------------------------------------- */

.main [data-testid="stVerticalBlockBorderWrapper"] {
    background-color: #FFFFFF;

    border-radius: 14px;

    box-shadow:
        0 4px 12px rgba(30, 65, 105, 0.06);
}


/* -------------------------------------------------------
   ALERT BOXES
------------------------------------------------------- */

.main [data-testid="stAlert"] p {
    color: #334155 !important;
    font-weight: 500;
}

.main [data-testid="stAlert"] {
    border-radius: 10px;
}


/* -------------------------------------------------------
   DATA TABLES
------------------------------------------------------- */

.main [data-testid="stDataFrame"] {
    background-color: #FFFFFF;

    border-radius: 12px;

    overflow: hidden;

    box-shadow:
        0 4px 12px rgba(30, 65, 105, 0.06);
}


/* -------------------------------------------------------
   NORMAL BUTTONS
------------------------------------------------------- */

.main .stButton > button {

    background: linear-gradient(
        90deg,
        #2563EB,
        #4F46E5
    ) !important;

    color: #FFFFFF !important;

    border: none !important;

    border-radius: 9px !important;

    font-weight: 700 !important;

    padding-left: 20px;
    padding-right: 20px;
}

.main .stButton > button:hover {

    box-shadow:
        0 5px 14px rgba(37, 99, 235, 0.25);

    color: #FFFFFF !important;
}


/* -------------------------------------------------------
   DOWNLOAD BUTTON
------------------------------------------------------- */

.main .stDownloadButton > button {

    background-color: #0F766E !important;

    color: #FFFFFF !important;

    border: none !important;

    border-radius: 9px !important;

    font-weight: 700 !important;
}

.main .stDownloadButton > button:hover {

    background-color: #0D625D !important;

    color: #FFFFFF !important;
}


/* -------------------------------------------------------
   DIVIDERS
------------------------------------------------------- */

.main hr {
    border-color: #DCE5EF;
}


/* -------------------------------------------------------
   CHART AREA
------------------------------------------------------- */

.main [data-testid="stVegaLiteChart"] {
    background-color: #FFFFFF;

    border-radius: 12px;

    padding: 8px;

    box-shadow:
        0 4px 12px rgba(30, 65, 105, 0.05);
}

</style>
    """,
    unsafe_allow_html=True
)


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def get_project_root():
    """
    Return the project root directory.
    """

    current_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    return os.path.abspath(
        os.path.join(
            current_dir,
            ".."
        )
    )


def get_risk_level(score):
    """
    Convert numerical risk score into
    a qualitative risk level.
    """

    if score <= 30:
        return "Low"

    elif score <= 50:
        return "Medium"

    elif score <= 70:
        return "High"

    else:
        return "Critical"


def get_risk_icon(level):
    """
    Return a visual indicator for
    each risk level.
    """

    if level == "Low":
        return "🟢"

    elif level == "Medium":
        return "🟠"

    elif level == "High":
        return "🔴"

    else:
        return "🚨"


def get_threat_type(issue):
    """
    Convert detailed threat explanations
    into simple threat categories.
    """

    if "Brute-force" in issue:
        return "Brute-force"

    elif "Odd-hour" in issue:
        return "Odd-hour Login"

    elif "sudo" in issue.lower():
        return "Excessive Sudo Usage"

    elif "Unusual source IP" in issue:
        return "Unusual Source IP"

    else:
        return "Other"


def load_evaluation_results():
    """
    Load previously generated detection
    evaluation results from CSV.
    """

    evaluation_path = os.path.join(
        get_project_root(),
        "data",
        "evaluation_results.csv"
    )

    if not os.path.exists(
        evaluation_path
    ):
        return None

    try:

        return pd.read_csv(
            evaluation_path
        )

    except Exception:

        return None


def get_baseline_user_count():
    """
    Count users available in the
    learned behaviour baseline.
    """

    baseline = load_behavior_baseline()

    if isinstance(
        baseline,
        dict
    ):
        return len(
            baseline
        )

    return 0


def get_manual_profile_count():
    """
    Count manually configured
    user profiles.
    """

    profiles = load_user_profiles()

    if isinstance(
        profiles,
        dict
    ):
        return len(
            profiles
        )

    return 0


# =========================================================
# LOAD SECURITY CONFIGURATION
# =========================================================

config = load_config()

baseline_user_count = (
    get_baseline_user_count()
)

manual_profile_count = (
    get_manual_profile_count()
)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.title(
        "🛡 Security Console"
    )

    st.write(
        "**Insider Threat Detection**"
    )

    st.caption(
        "Linux Authentication Log Analyzer"
    )

    st.divider()

    st.subheader(
        "🔎 Detection Rules"
    )

    st.write(
        "🔐 Brute-force attempts"
    )

    st.write(
        "🌙 Odd-hour logins"
    )

    st.write(
        "🔑 Excessive sudo usage"
    )

    st.write(
        "🌐 Unusual source IP"
    )

    st.divider()

    st.subheader(
        "⚙ Detection Policy"
    )

    st.write(
        "Brute-force threshold:"
    )

    st.caption(
        f"{config.get('brute_force_threshold', 5)} "
        "failed attempts within "
        f"{config.get('brute_force_window_minutes', 2)} "
        "minutes"
    )

    st.write(
        "Sudo threshold:"
    )

    st.caption(
        f"{config.get('sudo_threshold', 3)} "
        "privilege events"
    )

    st.divider()

    st.subheader(
        "🧠 Context-Aware Features"
    )

    st.write(
        "✅ Time-window detection"
    )

    st.write(
        "✅ User working profiles"
    )

    st.write(
        "✅ Behaviour baseline"
    )

    st.write(
        "✅ Source IP context"
    )

    st.write(
        "✅ Explainable alerts"
    )

    st.write(
        "✅ Weighted risk scoring"
    )

    st.write(
        "✅ Historical analysis"
    )

    st.divider()

    st.caption(
        "Cybersecurity Analytics Dashboard"
    )


# =========================================================
# MAIN HEADER
# =========================================================

st.title(
    "🛡 Insider Threat Detection"
)

st.subheader(
    "Linux Authentication Security Analytics Dashboard"
)

st.write(
    "Analyse Linux authentication logs using "
    "context-aware threat detection, user behaviour "
    "profiles, risk scoring and explainable alerts."
)

st.divider()


# =========================================================
# CONTEXT-AWARE DETECTION STATUS
# =========================================================

st.subheader(
    "🧠 Context-Aware Detection"
)

st.write(
    "The enhanced detection engine evaluates authentication "
    "events using timing, user behaviour, working profiles "
    "and source information instead of relying only on "
    "simple event counts."
)


context_col1, context_col2, context_col3, context_col4 = (
    st.columns(
        4
    )
)


with context_col1:

    st.metric(
        label="👥 Learned Users",
        value=baseline_user_count
    )


with context_col2:

    st.metric(
        label="🧑‍💼 Manual Profiles",
        value=manual_profile_count
    )


with context_col3:

    st.metric(
        label="⏱ Brute-force Window",
        value=(
            f"{config.get('brute_force_window_minutes', 2)} min"
        )
    )


with context_col4:

    st.metric(
        label="🌐 IP Context",
        value="Enabled"
    )


st.caption(
    "Learned users are obtained from the historical "
    "behaviour baseline. Manual profiles are configured "
    "through user_profiles.json."
)

st.divider()


# =========================================================
# DETECTION METHOD EVALUATION
# =========================================================

st.subheader(
    "📊 Detection Method Evaluation"
)

st.write(
    "Comparison of the basic rule-based approach with "
    "the enhanced context-aware approach using the "
    "controlled labelled evaluation dataset."
)


evaluation_df = (
    load_evaluation_results()
)


if evaluation_df is not None and not evaluation_df.empty:

    display_evaluation = (
        evaluation_df.copy()
    )

    percentage_columns = [
        "Precision",
        "Recall",
        "F1",
        "False Positive Rate"
    ]

    for column in percentage_columns:

        if column in display_evaluation.columns:

            display_evaluation[
                column
            ] = (
                display_evaluation[
                    column
                ]
                * 100
            ).round(
                1
            ).astype(
                str
            ) + "%"


    rename_columns = {
        "F1": "F1 Score",
        "TP": "True Positives",
        "FP": "False Positives",
        "TN": "True Negatives",
        "FN": "False Negatives"
    }

    display_evaluation = (
        display_evaluation.rename(
            columns=rename_columns
        )
    )


    st.dataframe(
        display_evaluation,
        use_container_width=True,
        hide_index=True
    )


    if (
        "Approach"
        in evaluation_df.columns
    ):

        comparison_columns = []

        for column in [
            "Precision",
            "Recall",
            "F1"
        ]:

            if column in evaluation_df.columns:

                comparison_columns.append(
                    column
                )


        if comparison_columns:

            chart_df = (
                evaluation_df[
                    [
                        "Approach"
                    ]
                    + comparison_columns
                ]
                .copy()
            )


            for column in comparison_columns:

                chart_df[
                    column
                ] = (
                    chart_df[
                        column
                    ]
                    * 100
                )


            chart_df = (
                chart_df.set_index(
                    "Approach"
                )
            )


            chart_df = (
                chart_df.rename(
                    columns={
                        "F1":
                            "F1 Score"
                    }
                )
            )


            st.subheader(
                "📈 Performance Comparison"
            )


            st.bar_chart(
                chart_df
            )


    st.caption(
        "The evaluation results apply to the controlled "
        "labelled test scenarios. They demonstrate the "
        "behaviour of the implemented detection logic and "
        "do not imply perfect performance in every "
        "real-world environment."
    )


else:

    st.info(
        "Evaluation results are not available. "
        "Run evaluate_detection.py to generate "
        "evaluation_results.csv."
    )


st.divider()


# =========================================================
# FILE UPLOAD
# =========================================================

st.subheader(
    "📂 Authentication Log Analysis"
)

st.write(
    "Upload a Linux authentication log file "
    "to begin context-aware security analysis."
)


uploaded_file = st.file_uploader(
    "Upload auth.log or text log file",
    type=[
        "log",
        "txt"
    ]
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


    # -----------------------------------------------------
    # Parse Logs
    # -----------------------------------------------------

    events = parse_logs(
        logs
    )


    # -----------------------------------------------------
    # Context-Aware Threat Detection
    # -----------------------------------------------------

    threats = analyze_threats(
        events
    )


    # -----------------------------------------------------
    # Risk Scoring
    # -----------------------------------------------------

    risks = calculate_risk(
        threats
    )


    # =====================================================
    # SECURITY OVERVIEW
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
        max(
            risks.values()
        )
        if risks
        else 0
    )

    highest_risk_level = (
        get_risk_level(
            highest_risk
        )
    )


    st.subheader(
        "📌 Security Overview"
    )


    col1, col2, col3, col4 = (
        st.columns(
            4
        )
    )


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
            label="🛡 Highest Risk",
            value=highest_risk,
            delta=highest_risk_level,
            delta_color="off"
        )


    # =====================================================
    # DATABASE
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
                "Analysis saved successfully "
                "to SQLite database."
            )

        else:

            st.warning(
                "No suspicious activity "
                "available to save."
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

            risk_icon = (
                get_risk_icon(
                    level
                )
            )


            with st.container(
                border=True
            ):

                user_column, risk_column = (
                    st.columns(
                        [
                            3,
                            1
                        ]
                    )
                )


                with user_column:

                    st.subheader(
                        f"👤 {user}"
                    )

                    st.write(
                        f"**Risk Score:** "
                        f"{score}/100"
                    )


                with risk_column:

                    st.subheader(
                        f"{risk_icon} {level}"
                    )


                for issue in issues:

                    if (
                        "Brute-force"
                        in issue
                    ):

                        st.error(
                            f"🔐 {issue}"
                        )


                    elif (
                        "Odd-hour"
                        in issue
                    ):

                        st.warning(
                            f"🌙 {issue}"
                        )


                    elif (
                        "sudo"
                        in issue.lower()
                    ):

                        st.warning(
                            f"🔑 {issue}"
                        )


                    elif (
                        "Unusual source IP"
                        in issue
                    ):

                        st.warning(
                            f"🌐 {issue}"
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
    # RISK ASSESSMENT + THREAT DISTRIBUTION
    # =====================================================

    st.divider()


    left_column, right_column = (
        st.columns(
            [
                1,
                1
            ]
        )
    )


    # -----------------------------------------------------
    # RISK ASSESSMENT
    # -----------------------------------------------------

    with left_column:

        st.subheader(
            "📊 Risk Assessment"
        )


        risk_table = []


        for user, score in risks.items():

            level = (
                get_risk_level(
                    score
                )
            )


            risk_table.append(
                {
                    "User":
                        user,

                    "Risk Score":
                        score,

                    "Risk Level":
                        (
                            f"{get_risk_icon(level)} "
                            f"{level}"
                        )
                }
            )


        if risk_table:

            risk_df = (
                pd.DataFrame(
                    risk_table
                )
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
    # THREAT DISTRIBUTION
    # -----------------------------------------------------

    with right_column:

        st.subheader(
            "📈 Threat Distribution"
        )


        threat_distribution = {
            "Brute-force": 0,
            "Odd-hour Login": 0,
            "Excessive Sudo Usage": 0,
            "Unusual Source IP": 0
        }


        for user, issues in threats.items():

            for issue in issues:

                threat_type = (
                    get_threat_type(
                        issue
                    )
                )


                if (
                    threat_type
                    in threat_distribution
                ):

                    threat_distribution[
                        threat_type
                    ] += 1


        chart_data = (
            pd.DataFrame(
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
        )


        chart_data = (
            chart_data[
                chart_data[
                    "Alerts"
                ] > 0
            ]
        )


        if not chart_data.empty:

            st.bar_chart(
                chart_data.set_index(
                    "Threat Type"
                )
            )


            st.caption(
                "Number of alerts generated "
                "for each detected threat category."
            )


        else:

            st.info(
                "No threat distribution available."
            )


    # =====================================================
    # AUTHENTICATION EVENT TIMELINE
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
                        event[
                            "timestamp"
                        ],

                    "User":
                        event[
                            "user"
                        ],

                    "Source IP":
                        event.get(
                            "source_ip",
                            "N/A"
                        ),

                    "Event":
                        event[
                            "event"
                        ]
                }
            )


    if timeline:

        timeline_df = (
            pd.DataFrame(
                timeline
            )
        )


        st.dataframe(
            timeline_df,
            use_container_width=True,
            hide_index=True
        )


    else:

        st.info(
            "No authentication events "
            "available for the timeline."
        )


    # =====================================================
    # EXPORT SECURITY RESULTS
    # =====================================================

    st.divider()


    st.subheader(
        "⬇ Export Security Results"
    )


    if risk_table:

        csv_data = (
            pd.DataFrame(
                risk_table
            )
            .to_csv(
                index=False
            )
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
        "🗄 Historical Threat Analysis"
    )


    history = (
        get_threat_history()
    )


    if history:

        history_table = []


        for record in history:

            stored_score = (
                record[3]
            )

            stored_level = (
                get_risk_level(
                    stored_score
                )
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
                        (
                            f"{get_risk_icon(stored_level)} "
                            f"{stored_level}"
                        )
                }
            )


        history_df = (
            pd.DataFrame(
                history_table
            )
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
# EMPTY DASHBOARD STATE
# =========================================================

else:

    st.info(
        "🔎 Upload a Linux authentication log file above "
        "to begin insider-threat analysis."
    )


    st.write("")


    col1, col2, col3, col4 = (
        st.columns(
            4
        )
    )


    with col1:

        with st.container(
            border=True
        ):

            st.subheader(
                "🔐 Brute-force"
            )

            st.write(
                "Uses both failed-attempt count "
                "and a configured time window."
            )


    with col2:

        with st.container(
            border=True
        ):

            st.subheader(
                "🌙 Login Context"
            )

            st.write(
                "Checks login time against user "
                "profiles and learned behaviour."
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


    with col4:

        with st.container(
            border=True
        ):

            st.subheader(
                "🌐 Source IP"
            )

            st.write(
                "Checks login source against trusted "
                "and historically observed addresses."
            )
