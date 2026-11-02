SEVERITY_SCORES = {
    "Low": 20,
    "Medium": 45,
    "High": 75,
    "Critical": 100,
}


def calculate_process_risk(process: dict) -> int:
    """Return a risk score from 0 to 100 for one detection."""

    severity = str(process.get("severity", "Low"))
    base_score = SEVERITY_SCORES.get(severity, 10)

    reason = str(process.get("reason", "")).lower()

    bonus = 0

    if "keylogger" in reason:
        bonus += 15

    if "credential" in reason or "password" in reason:
        bonus += 20

    if "multiple suspicious indicators" in reason:
        bonus += 10

    return min(base_score + bonus, 100)


def calculate_overall_risk(
    suspicious_processes: list[dict],
) -> tuple[int, str]:
    """Calculate the highest current risk and return score and level."""

    if not suspicious_processes:
        return 0, "Safe"

    scores = [
        calculate_process_risk(process)
        for process in suspicious_processes
    ]

    overall_score = max(scores)

    if overall_score >= 90:
        level = "Critical"
    elif overall_score >= 70:
        level = "High"
    elif overall_score >= 40:
        level = "Medium"
    elif overall_score > 0:
        level = "Low"
    else:
        level = "Safe"

    return overall_score, level