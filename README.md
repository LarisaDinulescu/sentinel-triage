# SentinelTriage

A Python-based security alert triage prototype.

## Current features

- Loads synthetic security alerts from JSON.
- Validates required fields and data types.
- Normalizes timestamps to UTC.
- Validates alert severity.
- Reports accepted and rejected events with explanations.
- Includes automated parser tests.

## Run

From the project root:

```bash
python3 src/main.py
```

## Run tests

```bash
python3 -m unittest discover -s tests -v
```

## Safety

All included alerts are synthetic. This prototype is not connected to a production SOC and is not intended to make autonomous incident decisions.