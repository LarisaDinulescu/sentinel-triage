
import argparse
import json
from pathlib import Path

from parser import load_alerts
from correlator import correlate_alerts
from triage import assess_case

DEFAULT_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "sample_alerts.json"
)


def main():
    command = argparse.ArgumentParser(
        description="SentinelTriage - validatore di alert sintetici"
    )

    command.add_argument(
        "--file",
        default=str(DEFAULT_FILE),
        help="Percorso del file JSON da controllare",
    )

    args = command.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8") as file:
            raw_data = json.load(file)

        if not isinstance(raw_data, list):
            print("ERRORE: il JSON deve contenere una lista.")
            raise SystemExit(1)

        total = len(raw_data)
        accepted, errors = load_alerts(args.file)

    except FileNotFoundError:
        print(f"ERRORE: file non trovato: {args.file}")
        raise SystemExit(1)

    except json.JSONDecodeError as error:
        print(
            "ERRORE: JSON non valido: "
            f"riga {error.lineno}, colonna {error.colno}"
        )
        raise SystemExit(1)

    except ValueError as error:
        print(f"ERRORE: {error}")
        raise SystemExit(1)

    rejected = total - len(accepted)
    triage_report = correlate_alerts(accepted)
    cases = triage_report["cases"]
    unmatched_alerts = triage_report["unmatched_alerts"]


    print()
    print("=" * 45)
    print("       SENTINELTRIAGE - REPORT")
    print("=" * 45)
    print(f"Eventi letti:        {total}")
    print(f"Eventi accettati:    {len(accepted)}")
    print(f"Eventi scartati:     {rejected}")
    print("=" * 45)

    if errors:
        print("\nDETTAGLIO ERRORI:")

        for error in errors:
            print(f"- {error}")

    else:
        print("\nNessun errore di validazione.")

    print()
    print("=" * 45)
    print("       REPORT DI TRIAGE")
    print("=" * 45)
    print(f"Casi investigativi:  {len(cases)}")
    print(f"Alert non correlati: {len(unmatched_alerts)}")

    for case in cases:
        assessment = assess_case(case)

        print()
        print(case["case_id"])
        print(f"  Priorità investigativa: {assessment['priority']}")
        print(f"  Scenario: {assessment['scenario']}")
        print(f"  Eventi: {', '.join(case['event_ids'])}")
        print(f"  Regole: {', '.join(case['rules_triggered'])}")

        print("  Motivazione:")
        for reason in assessment["rationale"]:
            print(f"    - {reason}")

        print("  Elementi da verificare:")
        for item in assessment["items_to_verify"]:
            print(f"    - {item}")

        print("  Azioni consigliate:")
        for action in assessment["recommended_actions"]:
            print(f"    - {action}")

        if case["indicators"]:
            print(f"  Indicatori: {case['indicators']}")


    print()
    print("ALERT NON CORRELATI")
    print("-" * 45)

    for alert in unmatched_alerts:
        print(
            f"{alert['alert_id']} | "
            f"{alert['timestamp']} | "
            f"{alert['event_type']} | "
            f"{alert['severity']}"
        )

    print()


if __name__ == "__main__":
    main()
