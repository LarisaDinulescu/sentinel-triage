# SentinelTriage

SentinelTriage is a Python-based security alert triage prototype that validates, normalizes, deduplicates, and correlates synthetic security events to support rule-based investigative prioritization.

The project demonstrates foundational Security Operations Center (SOC) workflows through modular code, deterministic detection rules, data-quality reporting, and automated unit tests.

## Key Features

- **Alert parsing and validation:** validates required fields, data types, timestamps, and severity values while reporting rejected events.
- **Timestamp normalization:** converts valid timestamps to UTC for consistent event processing.
- **Data quality reporting:** separates accepted and rejected events and explains validation failures.
- **Alert deduplication:** groups similar alerts within a configurable time window while preserving distinct failed-login attempts.
- **Event correlation:** identifies related activity using predefined event types, identities, source IP addresses, hosts, and time windows.
- **Authentication monitoring:** detects failed login attempts followed by a successful login for the same user and source IP.
- **Repeated login detection:** identifies bursts of failed authentication attempts against a single account.
- **Password spraying detection:** identifies repeated authentication failures from one source IP against multiple usernames.
- **Phishing-related correlation:** links email-link activity with subsequent unusual network connections for the same user and host.
- **Investigative case generation:** groups correlated alerts into investigation cases and reports unmatched events.
- **Rule-based triage:** assigns HIGH, MEDIUM, or LOW investigative priority with explanations, items to verify, and recommended actions.
- **Automated testing:** covers parsing, validation, deduplication, correlation rules, triage decisions, and edge cases.

## Project Structure

```text
sentinel-triage/
├── data/
│   └── sample_alerts.json
├── src/
│   ├── main.py
│   ├── parser.py
│   ├── correlator.py
│   └── triage.py
├── tests/
│   ├── test_parser.py
│   ├── test_correlator.py
│   └── test_triage.py
├── generate_alerts.py
└── README.md
```

## Requirements

- Python 3
- No third-party dependencies are required for the current implementation.

## Run the Project

From the project root, run:

```bash
python3 src/main.py
```

The program processes the sample dataset and reports data-quality results, correlated investigative cases, priorities, supporting rationale, recommended actions, and unmatched alerts.

## Run Tests

Run the automated test suite with:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover parser validation, timestamp handling, duplicate grouping, authentication-event correlation, password spraying, phishing-related correlation, triage prioritization, and edge cases.

## Detection and Triage Logic

SentinelTriage uses deterministic rules and predefined time windows to identify patterns that may warrant investigation. Triage priority represents an investigative recommendation, not a confirmed incident severity or proof of compromise.

The output is intended to help an analyst decide what to review next. Recommended actions and explanations are rule-based and should be validated against the original events and additional context.

## Scope and Limitations

SentinelTriage is an educational prototype that uses synthetic security data. It is not connected to a production Security Operations Center (SOC), SIEM, threat-intelligence platform, or live telemetry source.

Its detection rules are predefined and may produce false positives or miss activity outside their configured conditions. The results require human review and should not be treated as confirmation of malicious activity.
