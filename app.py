
import html
import json
import sys
from datetime import datetime
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
DEFAULT_FILE = ROOT / "data" / "sample_alerts.json"

sys.path.insert(0, str(SRC))

from parser import load_alerts
from correlator import correlate_alerts
from triage import assess_case


st.set_page_config(
    page_title="SentinelTriage",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SentinelTriage")
st.caption("Security Alert Triage Dashboard")

with st.sidebar:
    st.header("Data source")
    uploaded_file = st.file_uploader(
        "Upload alerts JSON",
        type=["json"],
    )
    st.caption("Upload a JSON list of synthetic security alerts.")

@st.cache_data
def load_dashboard_data(file_bytes):
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".json") as temp:
        temp.write(file_bytes)
        temp.flush()
        accepted, errors = load_alerts(temp.name)

    report = correlate_alerts(accepted)
    cases = []

    for case in report["cases"]:
        assessment = assess_case(case)
        cases.append({**case, **assessment})

    return accepted, errors, cases, report["unmatched_alerts"]


try:
    if uploaded_file is not None:
        raw_bytes = uploaded_file.getvalue()
        raw_data = json.loads(raw_bytes)

        if not isinstance(raw_data, list):
            st.error("The uploaded JSON must contain a list of events.")
            st.stop()
    else:
        raw_bytes = DEFAULT_FILE.read_bytes()
        raw_data = json.loads(raw_bytes)

    accepted, errors, cases, unmatched = load_dashboard_data(raw_bytes)

except (OSError, json.JSONDecodeError, ValueError) as error:
    st.error(f"Unable to process the input file: {error}")
    st.stop()

total_alerts = len(raw_data)
accepted_count = len(accepted)
rejected_count = len(errors)
case_count = len(cases)

# Overview
st.header("1. Overview")

high_count = sum(c["priority"] == "HIGH" for c in cases)
medium_count = sum(c["priority"] == "MEDIUM" for c in cases)
low_count = sum(c["priority"] == "LOW" for c in cases)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Alerts processed", total_alerts)
col2.metric("Accepted alerts", accepted_count)
col3.metric("Investigative cases", case_count)
col4.metric("Unmatched alerts", len(unmatched))

priority_col1, priority_col2, priority_col3 = st.columns(3)
priority_col1.metric("HIGH priority", high_count)
priority_col2.metric("MEDIUM priority", medium_count)
priority_col3.metric("LOW priority", low_count)

if errors:
    with st.expander(f"Validation errors ({len(errors)})"):
        for error in errors:
            st.write(f"- {error}")

st.subheader("Cases by priority")
st.bar_chart(
    {
        "Cases": {
            "HIGH": high_count,
            "MEDIUM": medium_count,
            "LOW": low_count,
        }
    }
)

# Case queue
st.header("2. Case queue")

priority_options = ["HIGH", "MEDIUM", "LOW"]
selected_priorities = st.multiselect(
    "Filter by priority",
    priority_options,
    default=priority_options,
)

all_rules = sorted({
    rule
    for case in cases
    for rule in case.get("rules_triggered", [])
})

selected_rules = st.multiselect(
    "Filter by detection rule",
    all_rules,
    default=[],
)

date_values = [
    event["timestamp"]
    for case in cases
    for event in case.get("events", [])
    if event.get("timestamp")
]

if date_values:
    parsed_dates = [
        datetime.fromisoformat(value.replace("Z", "+00:00")).date()
        for value in date_values
    ]
    min_date, max_date = min(parsed_dates), max(parsed_dates)

    date_range = st.date_input(
        "Filter by event date",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
    )
else:
    date_range = ()

filtered_cases = []

for case in cases:
    if case["priority"] not in selected_priorities:
        continue

    rules = set(case.get("rules_triggered", []))
    if selected_rules and not rules.intersection(selected_rules):
        continue

    if date_range and len(date_range) == 2:
        case_dates = [
            datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            ).date()
            for event in case.get("events", [])
            if event.get("timestamp")
        ]

        if not case_dates or not any(
            date_range[0] <= day <= date_range[1]
            for day in case_dates
        ):
            continue

    filtered_cases.append(case)

st.caption(f"{len(filtered_cases)} cases match the selected filters.")

if filtered_cases:
    st.dataframe(
        [
            {
                "Case ID": case["case_id"],
                "Priority": case["priority"],
                "Scenario": case["scenario"],
                "Events": len(case.get("events", [])),
                "Rules": ", ".join(case.get("rules_triggered", [])),
            }
            for case in filtered_cases
        ],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No cases match the selected filters.")

# Case details
st.header("3. Case details")

if filtered_cases:
    selected_id = st.selectbox(
        "Select a case",
        [case["case_id"] for case in filtered_cases],
    )
    selected_case = next(
        case for case in filtered_cases
        if case["case_id"] == selected_id
    )

    st.subheader(
        f"{selected_case['case_id']} — {selected_case['scenario']}"
    )
    st.metric("Investigative priority", selected_case["priority"])

    st.markdown("**Triggered rules**")
    for rule in selected_case.get("rules_triggered", []):
        st.code(rule)

    st.markdown("**Rationale**")
    for reason in selected_case.get("rationale", []):
        st.write(f"- {reason}")

    st.markdown("**Items to verify**")
    for item in selected_case.get("items_to_verify", []):
        st.write(f"- {item}")

    st.markdown("**Recommended actions**")
    for action in selected_case.get("recommended_actions", []):
        st.write(f"- {action}")

    st.markdown("**Indicators**")
    st.json(selected_case.get("indicators", {}))

    st.markdown("**Event timeline**")
    timeline_events = sorted(
        selected_case.get("events", []),
        key=lambda event: event.get("timestamp", ""),
    )

    for event in timeline_events:
        st.markdown(
            f"- **{event.get('timestamp', 'Unknown time')}** — "
            f"`{event.get('event_type', 'unknown')}` | "
            f"{event.get('severity', 'unknown')} | "
            f"{event.get('username', 'unknown user')} | "
            f"{event.get('source_ip', 'unknown IP')}"
        )

    with st.expander("Raw case data"):
        st.json(selected_case)
else:
    st.info("Select filters that return at least one case to view details.")

# Export
st.header("4. Export")

export_report = {
    "summary": {
        "total_alerts": total_alerts,
        "accepted_alerts": accepted_count,
        "rejected_alerts": rejected_count,
        "investigative_cases": case_count,
        "unmatched_alerts": len(unmatched),
    },
    "validation_errors": errors,
    "cases": cases,
    "unmatched_alerts": unmatched,
}

json_bytes = json.dumps(
    export_report,
    indent=2,
    ensure_ascii=False,
    default=str,
).encode("utf-8")

st.download_button(
    "Download JSON report",
    data=json_bytes,
    file_name="sentineltriage-report.json",
    mime="application/json",
)

html_cases = []

for case in cases:
    rationale = "".join(
        f"<li>{html.escape(str(item))}</li>"
        for item in case.get("rationale", [])
    )
    actions = "".join(
        f"<li>{html.escape(str(item))}</li>"
        for item in case.get("recommended_actions", [])
    )
    html_cases.append(
        f"<section><h2>{html.escape(case['case_id'])}</h2>"
        f"<p>Priority: <strong>{html.escape(case['priority'])}</strong></p>"
        f"<p>Scenario: {html.escape(case['scenario'])}</p>"
        f"<h3>Rationale</h3><ul>{rationale}</ul>"
        f"<h3>Recommended actions</h3><ul>{actions}</ul></section>"
    )

html_report = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelTriage Report</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 1000px;
margin: 2rem auto; padding: 0 1rem; color: #222; }}
section {{ border-bottom: 1px solid #ddd; padding: 1rem 0; }}
</style>
</head>
<body>
<h1>SentinelTriage Report</h1>
<p>Alerts processed: {total_alerts}</p>
<p>Accepted: {accepted_count} | Rejected: {rejected_count}</p>
<p>Cases: {case_count} | Unmatched alerts: {len(unmatched)}</p>
{"".join(html_cases)}
</body>
</html>"""

st.download_button(
    "Download HTML report",
    data=html_report.encode("utf-8"),
    file_name="sentineltriage-report.html",
    mime="text/html",
)

st.caption(
    "Educational prototype using synthetic data. "
    "Priorities support investigation and do not prove compromise."
)
