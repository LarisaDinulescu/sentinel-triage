
"""Rule-based investigative prioritization for SentinelTriage."""

HIGH_PRIORITY_RULES = {
    "failed_then_successful_login",
    "email_click_then_unusual_network",
    "repeated_failed_logins",
}

SCENARIOS = {
    "failed_then_successful_login": "Authentication",
    "email_click_then_unusual_network": "Possible phishing",
    "repeated_failed_logins": "Repeated authentication failures",
    "deduplication": "Repeated alerts",
}


def assess_case(case):
    """
    Assign an investigative priority using documented rules.

    Priority is not a determination of incident severity or compromise.
    """
    rules = set(case.get("rules_triggered", []))
    events = case.get("events", [])
    missing = case.get("missing_information", [])

    severities = {
        str(event.get("severity", "")).lower()
        for event in events
    }

    # Determine the scenario independently of missing information.
    scenario = next(
        (
            SCENARIOS[rule]
            for rule in (
                "failed_then_successful_login",
                "email_click_then_unusual_network",
                "repeated_failed_logins",
                "deduplication",
            )
            if rule in rules
        ),
        "General investigation",
    )

    rationale = []
    items_to_verify = []
    recommended_actions = []

    if "failed_then_successful_login" in rules:
        priority = "HIGH"
        rationale.append(
            "Failed login attempts preceded a successful login "
            "for the same user and source IP."
        )
        items_to_verify.append(
            "The successful login has not been proven malicious."
        )
        recommended_actions.append(
            "Review authentication logs, source IP context, "
            "and whether the login was legitimate."
        )

    elif "email_click_then_unusual_network" in rules:
        priority = "HIGH"
        rationale.append(
            "A suspicious email-link click preceded an unusual "
            "network connection for the same user and host."
        )
        items_to_verify.append(
            "The connection has not been proven to result "
            "from a compromise."
        )
        recommended_actions.append(
            "Inspect the original email, destination, endpoint "
            "telemetry, and network connection details."
        )

    elif "repeated_failed_logins" in rules:
        priority = "HIGH"
        rationale.append(
            "Repeated failed authentication attempts matched "
            "a configured detection threshold."
        )
        items_to_verify.append(
            "The pattern may have legitimate explanations and "
            "does not prove an attack or account compromise."
        )
        recommended_actions.append(
            "Review authentication logs, affected accounts, "
            "source IP reputation, and any subsequent successful logins."
        )

    elif "high" in severities or "critical" in severities:
        priority = "MEDIUM"
        rationale.append(
            "At least one correlated alert has high or critical "
            "reported severity, but the case does not match "
            "a defined high-priority sequence."
        )
        items_to_verify.append(
            "Confirm the reported severity and assess the "
            "context of the affected activity."
        )
        recommended_actions.append(
            "Review the original alerts and validate the "
            "reported severity."
        )

    else:
        priority = "LOW"
        rationale.append(
            "The case does not match a defined high-priority "
            "sequence and contains no high or critical "
            "reported severity."
        )
        items_to_verify.append(
            "Check whether additional context changes "
            "the investigative priority."
        )
        recommended_actions.append(
            "Review the correlated events and confirm "
            "that the grouping is meaningful."
        )

    if len(rules) > 1:
        rationale.append(
            "Multiple correlation rules contributed to this case."
        )

    if missing:
        items_to_verify.extend(missing)
        rationale.append(
            "Some information is missing; confidence in the "
            "assessment may therefore be limited."
        )

    return {
        "priority": priority,
        "scenario": scenario,
        "rationale": rationale,
        "items_to_verify": items_to_verify,
        "recommended_actions": recommended_actions,
    }
