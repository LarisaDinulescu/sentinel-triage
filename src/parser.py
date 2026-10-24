
import json
from datetime import datetime, timezone
from pathlib import Path


# Campi che ogni alert deve contenere.
REQUIRED_FIELDS = [
    "alert_id",
    "timestamp",
    "event_type",
    "severity",
    "source_ip",
    "username",
    "hostname",
    "description",
    "source",
]

# Severità che accettiamo.
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


def parse_timestamp(value):
    """Controlla il timestamp e lo converte in UTC."""
    if not isinstance(value, str):
        raise ValueError("il timestamp deve essere una stringa")

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        raise ValueError("timestamp non valido")

    if parsed.tzinfo is None:
        raise ValueError(
            "il timestamp deve includere il fuso orario"
        )

    return (
        parsed.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def load_alerts(file_path):
    """Carica gli alert e separa quelli validi da quelli errati."""
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(
            "il JSON deve contenere una lista di eventi"
        )

    accepted = []
    errors = []

    for index, event in enumerate(data, start=1):
        if not isinstance(event, dict):
            errors.append(
                f"Evento {index}: deve essere un oggetto JSON"
            )
            continue

        event_errors = []

        # 1. Controlla i campi obbligatori.
        for field in REQUIRED_FIELDS:
            if field not in event:
                event_errors.append(
                    f"manca il campo {field}"
                )

        # 2. Controlla che tutti i campi siano stringhe.
        for field in REQUIRED_FIELDS:
            if (
                field in event
                and not isinstance(event[field], str)
            ):
                event_errors.append(
                    f"il campo {field} deve essere una stringa"
                )

        # 3. Controlla e normalizza il timestamp.
        if isinstance(event.get("timestamp"), str):
            try:
                normalized_timestamp = parse_timestamp(
                    event["timestamp"]
                )
            except ValueError as error:
                event_errors.append(str(error))
            else:
                event["timestamp"] = normalized_timestamp

        # 4. Controlla e normalizza la severità.
        if isinstance(event.get("severity"), str):
            severity = event["severity"].strip().lower()

            if severity not in ALLOWED_SEVERITIES:
                event_errors.append(
                    "severità non riconosciuta: "
                    f"{event['severity']!r}"
                )
            else:
                event["severity"] = severity

        # 5. Accetta l'evento solo se non ci sono errori.
        if event_errors:
            for error in event_errors:
                errors.append(
                    f"Evento {index}: {error}"
                )
            continue

        accepted.append(event)

    return accepted, errors
