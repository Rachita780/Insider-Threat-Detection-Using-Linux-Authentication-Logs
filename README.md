# Insider Threat Detection Using Linux Authentication Logs

A context-aware security analysis system designed to identify suspicious user behaviour by analysing Linux authentication logs. The project combines structured log parsing, behaviour profiling, threat detection, weighted risk scoring, explainable alerts, historical storage, and an interactive Streamlit dashboard.

## Introduction

Insider threats are a significant cybersecurity concern because legitimate users may misuse authorised access or perform activities that differ from their normal behaviour. Linux authentication logs contain useful information such as login attempts, timestamps, source IP addresses, usernames, and privileged activity that can support security analysis.

This project implements a context-aware Insider Threat Detection System for Linux authentication logs. Instead of relying only on fixed event counts, the system also considers time-related information, user-specific working patterns, previously observed behaviour, and known source IP addresses.

The system is designed to identify suspicious authentication behaviour while also explaining why an activity was flagged, allowing security analysts to prioritise events that require further investigation.

## Objectives

- To analyse Linux authentication logs and extract relevant authentication events
- To identify suspicious user behaviour using context-aware detection
- To consider user-specific login times, historical behaviour, and source-IP information
- To calculate weighted risk scores and assign risk levels
- To generate explainable security alerts
- To present results through an interactive Streamlit dashboard
- To store historical threat information using SQLite
- To export analysed results in CSV format
- To evaluate context-aware detection against a basic rule-based detector

## System Features

### Threat Detection Capabilities

#### Rapid Failed Login Detection
Identifies repeated failed authentication attempts occurring within a configurable time window.

In the current prototype configuration, five failed login attempts within two minutes can trigger a brute-force alert.

#### Unusual Login Time Detection
Identifies successful logins occurring outside a user's expected login-time behaviour.

The system can use:
- Manually configured user working hours
- Historical successful login behaviour
- Default configured odd-hour rules when user-specific information is unavailable

#### Excessive Sudo Activity
Detects repeated sudo or privileged activity that may require further investigation.

Normal sudo usage is not automatically treated as malicious.

#### Unusual Source IP Detection
Identifies successful logins originating from source IP addresses that have not previously been observed or manually marked as trusted for the user.

An unfamiliar IP address does not automatically indicate an attack; it is treated as an activity requiring additional investigation.

## Context-Aware Behaviour Profiling

The system uses historical successful login events to create a behaviour baseline for users.

The baseline records:

- Previously observed login hours
- Known source IP addresses
- Successful login activity

User-specific context is selected using the following priority:

1. Manually configured user profile
2. Learned historical behaviour baseline
3. Default configured detection rules

This helps reduce unnecessary alerts for users whose normal working patterns differ from standard working hours, such as night-shift users.

## Risk Scoring Mechanism

Each suspicious behaviour contributes a configurable weighted value to the user's overall risk score.

Current prototype weights:

- Brute-force behaviour: 50
- Excessive sudo activity: 40
- Unusual login time: 30
- Unusual source IP: 20

The final risk score is capped at 100.

Risk levels used in the dashboard:

- Low: 0–30
- Medium: 31–50
- High: 51–70
- Critical: 71–100

These thresholds and weights are prototype-defined values used for prioritisation and can be modified through the configuration.

## Interactive Dashboard

The Streamlit-based dashboard provides:

- Authentication-log upload and analysis
- Total event count
- Suspicious user count
- Total alert count
- Highest detected risk level
- Context-aware threat alerts
- Risk scores and risk levels
- Threat explanations
- Threat distribution visualisation
- Authentication event timeline
- Behavioural context information
- Detection evaluation results
- Historical threat records stored in SQLite
- CSV export of analysed results

## Detection Evaluation

The project includes two detection approaches:

### Basic Rule-Based Detector

The basic detector uses simpler detection logic without user-specific behavioural or source-IP context.

### Context-Aware Detector

The context-aware detector considers:

- Time windows
- User working patterns
- Historical login behaviour
- Previously observed source IP addresses

The two approaches were compared using a controlled labelled authentication-log dataset containing both normal and suspicious activities.

### Evaluation Results

| Metric | Basic Detector | Context-Aware Detector |
|---|---:|---:|
| True Positives | 30 | 40 |
| False Positives | 20 | 0 |
| True Negatives | 340 | 360 |
| False Negatives | 10 | 0 |
| Precision | 0.600 | 1.000 |
| Recall | 0.750 | 1.000 |
| F1-Score | 0.667 | 1.000 |
| False Positive Rate | 0.056 | 0.000 |

The context-aware detector correctly identified all 40 expected suspicious cases in the defined controlled evaluation scenarios.

These results validate the implemented detection logic under the controlled test conditions and should not be interpreted as proof of perfect performance on real-world organisational data.

## Technologies Used

- Python – Core programming language
- Streamlit – Interactive dashboard
- Pandas – Data processing and analysis
- SQLite – Historical threat-data storage
- JSON – Configuration, user profiles, and behaviour baseline
- CSV – Evaluation data and analysed-result export

## Project Structure

```text
insider_threat_log_analyzer/
│
├── config.json
├── user_profiles.json
├── behavior_baseline.json
├── requirements.txt
├── README.md
│
├── data/
├── docs/
├── logs/
├── output/
├── reports/
│
└── src/
    ├── log_parser.py
    ├── threat_analyzer.py
    ├── risk_scoring.py
    ├── behavior_baseline.py
    ├── basic_analyzer.py
    ├── evaluate_detection.py
    ├── database.py
    └── dashboard.py
