from datetime import datetime, timedelta, timezone


# Finestre temporali esplicite delle regole.
DEDUP_WINDOW_MINUTES = 2
LOGIN_WINDOW_MINUTES = 10
EMAIL_NETWORK_WINDOW_MINUTES = 30


def _event_time(alert):
    """Converte il timestamp normalizzato in un datetime."""
    value = alert["timestamp"].replace("Z", "+00:00")
    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        raise ValueError(
            f"Timestamp senza fuso orario: {alert['alert_id']}"
        )

    return parsed.astimezone(timezone.utc)


def _dedup_key(alert):
    """Attributi usati per riconoscere possibili duplicati."""
    fields = (
        "event_type",
        "severity",
        "source_ip",
        "username",
        "hostname",
        "description",
        "source",
    )

    return tuple(alert.get(field) for field in fields)


def _new_candidate(alerts, rule, reason):
    """Crea un gruppo candidato a diventare un caso."""
    return {
        "event_ids": {a["alert_id"] for a in alerts},
        "rules": {rule},
        "reasons": {reason},
    }





def _deduplicate(alerts):
    """Raggruppa possibili duplicati entro una finestra fissa."""

    groups = {}

    # Raggruppa gli alert con gli stessi attributi significativi.
    for alert in sorted(alerts, key=_event_time):
        # I login falliti possono rappresentare tentativi distinti.
        # Non deduplicarli automaticamente.
        if alert.get("event_type") == "failed_login":
            continue

        key = _dedup_key(alert)
        groups.setdefault(key, []).append(alert)

    candidates = []
    reason = (
        "Alert con gli stessi attributi significativi "
        f"entro una finestra di {DEDUP_WINDOW_MINUTES} minuti"
    )

    for group in groups.values():
        cluster = []
        cluster_start = None

        for alert in group:
            current_time = _event_time(alert)

            # Se l'alert è fuori dalla finestra, chiudi il cluster.
            if (
                cluster
                and current_time - cluster_start
                > timedelta(minutes=DEDUP_WINDOW_MINUTES)
            ):
                if len(cluster) > 1:
                    candidates.append(
                        _new_candidate(
                            cluster,
                            "deduplication",
                            reason,
                        )
                    )

                cluster = []
                cluster_start = None

            # Inizia un nuovo cluster.
            if not cluster:
                cluster_start = current_time

            cluster.append(alert)

        # Gestisce l'ultimo cluster del gruppo.
        if len(cluster) > 1:
            candidates.append(
                _new_candidate(
                    cluster,
                    "deduplication",
                    reason,
                )
            )

    return candidates





def _correlate_logins(alerts):
    """Collega login falliti a un successivo login riuscito."""
    failed = [
        a for a in alerts
        if a["event_type"] == "failed_login"
    ]
    successful = [
        a for a in alerts
        if a["event_type"] == "successful_login"
    ]

    candidates = []

    for success in successful:
        matching_failures = []

        for failure in failed:
            elapsed = (
                _event_time(success) - _event_time(failure)
            )

            same_user = failure["username"] == success["username"]
            same_ip = failure["source_ip"] == success["source_ip"]

            if (
                same_user
                and same_ip
                and timedelta(0) < elapsed
                <= timedelta(minutes=LOGIN_WINDOW_MINUTES)
            ):
                matching_failures.append(failure)

        if matching_failures:
            matching_failures.append(success)

            candidates.append(
                _new_candidate(
                    matching_failures,
                    "failed_then_successful_login",
                    (
                        "Login falliti seguiti da un login riuscito "
                        f"per lo stesso utente e IP entro "
                        f"{LOGIN_WINDOW_MINUTES} minuti"
                    ),
                )
            )

    return candidates


def _correlate_email_network(alerts):
    """Collega un clic sospetto a una successiva connessione anomala."""
    clicks = [
        a for a in alerts
        if a["event_type"] == "email_link_clicked"
    ]
    connections = [
        a for a in alerts
        if a["event_type"] == "unusual_network_connection"
    ]

    candidates = []

    for click in clicks:
        for connection in connections:
            elapsed = (
                _event_time(connection) - _event_time(click)
            )

            same_user = click["username"] == connection["username"]
            same_host = click["hostname"] == connection["hostname"]

            if (
                same_user
                and same_host
                and timedelta(0) < elapsed
                <= timedelta(minutes=EMAIL_NETWORK_WINDOW_MINUTES)
            ):
                candidates.append(
                    _new_candidate(
                        [click, connection],
                        "email_click_then_unusual_network",
                        (
                            "Clic su link sospetto seguito da "
                            "connessione anomala per lo stesso "
                            "utente e dispositivo entro "
                            f"{EMAIL_NETWORK_WINDOW_MINUTES} minuti"
                        ),
                    )
                )

    return candidates



def _merge_candidates(candidates):
    """
    Unisce i candidati che condividono eventi.
    Conserva tutte le regole e le motivazioni attivate.
    """
    merged = []

    for candidate in candidates:
        current = {
            "event_ids": set(candidate["event_ids"]),
            "rules": set(candidate["rules"]),
            "reasons": set(candidate["reasons"]),
        }

        changed = True

        while changed:
            changed = False

            for existing in merged[:]:
                overlaps = bool(
                    existing["event_ids"] & current["event_ids"]
                )

                if overlaps:
                    current["event_ids"].update(
                        existing["event_ids"]
                    )
                    current["rules"].update(existing["rules"])
                    current["reasons"].update(existing["reasons"])
                    merged.remove(existing)
                    changed = True

        merged.append(current)

    return merged



def _build_case(candidate, alerts_by_id, number):
    """Costruisce un caso investigativo leggibile."""
    events = [
        alerts_by_id[event_id]
        for event_id in candidate["event_ids"]
    ]
    events.sort(key=_event_time)

    indicators = {}

    for field in ("username", "source_ip", "hostname"):
        values = sorted({
            event[field]
            for event in events
            if event.get(field)
        })

        if values:
            indicators[field] = values

    missing_information = []

    if not any(e.get("username") for e in events):
        missing_information.append("Nome utente non disponibile")

    if not any(e.get("source_ip") for e in events):
        missing_information.append("Indirizzo IP non disponibile")

    if not any(e.get("hostname") for e in events):
        missing_information.append("Dispositivo non disponibile")

    suggestions = [
        "Verificare la timeline e confermare la correlazione.",
        "Controllare i log originali prima di concludere l'indagine.",
    ]

    if "failed_then_successful_login" in candidate["rules"]:
        suggestions.append(
            "Verificare con l'utente la legittimità del login riuscito."
        )

    if "email_click_then_unusual_network" in candidate["rules"]:
        suggestions.append(
            "Esaminare il messaggio originale e i dettagli "
            "della connessione."
        )

    if "deduplication" in candidate["rules"]:
        suggestions.append(
            "Verificare che gli alert raggruppati siano "
            "duplicati reali prima di ridurre il rumore."
        )

    return {
        "case_id": f"CASE-{number:03d}",
        "event_ids": [e["alert_id"] for e in events],
        "events": events,
        "timeline": [
            {
                "timestamp": e["timestamp"],
                "alert_id": e["alert_id"],
                "event_type": e["event_type"],
                "description": e["description"],
            }
            for e in events
        ],
        "rules_triggered": sorted(candidate["rules"]),
        "correlation_reasons": sorted(candidate["reasons"]),
        "indicators": indicators,
        "missing_information": missing_information,
        "analyst_suggestions": suggestions,
    }


def correlate_alerts(alerts):
    """
    Restituisce i casi investigativi e gli alert non correlati.

    Gli alert originali vengono conservati e non sono modificati.
    """
    candidates = _deduplicate(alerts)
    candidates.extend(_correlate_logins(alerts))
    candidates.extend(_correlate_email_network(alerts))

    merged = _merge_candidates(candidates)

    alerts_by_id = {
        alert["alert_id"]: alert
        for alert in alerts
    }

    merged.sort(
        key=lambda candidate: min(
            _event_time(alerts_by_id[event_id])
            for event_id in candidate["event_ids"]
        )
    )

    cases = [
        _build_case(candidate, alerts_by_id, index)
        for index, candidate in enumerate(merged, start=1)
    ]

    correlated_ids = {
        event_id
        for candidate in merged
        for event_id in candidate["event_ids"]
    }

    unmatched_alerts = [
        alert for alert in alerts
        if alert["alert_id"] not in correlated_ids
    ]

    return {
        "cases": cases,
        "unmatched_alerts": unmatched_alerts,
    }