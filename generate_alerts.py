import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

output = Path("data/sample_alerts.json")
events = []

start = datetime(2026, 10, 24, 8, 0, tzinfo=timezone.utc)


def add_event(i, event_type, severity="low", **overrides):
    event = {
        "alert_id": f"ALT-{i:04d}",
        "timestamp": (
            start + timedelta(minutes=i)
        ).isoformat().replace("+00:00", "Z"),
        "event_type": event_type,
        "severity": severity,
        "source_ip": "192.0.2.25",
        "username": "user_demo",
        "hostname": "pc-demo-01",
        "description": f"Synthetic event: {event_type}",
        "source": "synthetic",
    }

    event.update(overrides)
    events.append(event)


# Scenario 1: tentativi di accesso falliti
for i in range(1, 21):
    add_event(
        i,
        "failed_login",
        "low",
        username=f"user{i % 5:02d}",
    )

# Scenario 2: molti fallimenti seguiti da un accesso riuscito
for i in range(21, 36):
    add_event(
        i,
        "failed_login",
        "medium",
        username="user_demo",
        source_ip="192.0.2.30",
    )

add_event(
    36,
    "successful_login",
    "medium",
    username="user_demo",
    source_ip="192.0.2.30",
)

# Scenario 3: attività sospette e alert duplicato
for i in range(37, 47):
    add_event(i, "suspicious_process", "medium")

duplicate = dict(events[-1])
events.append(duplicate)

# Scenario 4: connessioni insolite isolate
for i in range(48, 63):
    add_event(
        i,
        "unusual_network_connection",
        "high",
        source_ip="192.0.2.40",
    )

# Scenario 5: email sospetta e successiva attività
add_event(
    63,
    "suspicious_email",
    "medium",
    username="user_mail_demo",
)
add_event(
    64,
    "email_link_clicked",
    "medium",
    username="user_mail_demo",
)
add_event(
    65,
    "unusual_network_connection",
    "high",
    username="user_mail_demo",
    source_ip="192.0.2.50",
)

# Scenario 6: attività normali
for i in range(66, 86):
    add_event(
        i,
        "routine_login",
        "low",
        description="Synthetic routine login for testing",
    )

# Scenario 7: altri eventi misti
event_types = [
    "successful_login",
    "failed_login",
    "routine_login",
    "suspicious_process",
    "unusual_network_connection",
]

for i in range(86, 121):
    event_type = event_types[i % len(event_types)]
    severity = (
        "high"
        if event_type == "unusual_network_connection"
        else "low"
    )

    add_event(i, event_type, severity, username=f"user{i % 7:02d}")

# Tre errori intenzionali per testare il parser
events[10]["timestamp"] = "ieri mattina"
events[40]["severity"] = "urgent"
del events[75]["username"]


add_event(
    121,
    "routine_login",
    "low",
    username="user_extra",
)


output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    json.dumps(events, indent=2),
    encoding="utf-8",
)

print(f"Creati {len(events)} eventi in {output}")
