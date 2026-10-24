# SentinelTriage

SentinelTriage is a Python-based security alert triage prototype designed to process, validate, deduplicate, and correlate synthetic security events.

The project demonstrates foundational Security Operations Center (SOC) alert-triage concepts through modular Python code, structured event processing, and automated unit tests.

## Key Features

- **Alert parsing and validation:** validates required fields, data types, timestamps, and severity values.
- **Timestamp normalization:** converts valid timestamps to UTC.
- **Data quality reporting:** separates accepted and rejected events and explains validation failures.
- **Alert deduplication:** groups similar alerts within a configurable time window while preserving distinct failed-login attempts.
- **Event correlation:** identifies potential security scenarios, including repeated failed logins followed by a successful login and email-link activity followed by an unusual network connection.
- **Investigative case generation:** combines related alerts into cases for further investigation.
- **Automated testing:** tests parsing, validation, deduplication, correlation rules, and edge cases.

## Project Structure

```text
sentinel-triage/
├── data/
│   └── sample_alerts.json
├── src/
│   ├── main.py
│   ├── parser.py
│   └── correlator.py
├── tests/
│   ├── test_parser.py
│   └── test_correlator.py
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

The program processes the sample dataset and reports accepted and rejected events, investigative cases, and unmatched alerts.

## Run Tests

Run the automated test suite with:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover parser validation, duplicate grouping, login-event correlation, email/network correlation, and consistent alert handling.

## Scope and Limitations

SentinelTriage is an educational prototype that uses synthetic security data. Its correlation rules are deterministic and based on predefined conditions. It is not connected to a production Security Operations Center (SOC), and its output requires human review.

The project demonstrates Python programming, data validation, event processing, basic security detection logic, and automated testing.