from datetime import datetime, timezone

from app.core.database import get_session, Alert, Incident


def create_alert_and_incident(
    threat_score,
    severity,
    message,
    event_type="suspicious_activity",
    file_path=None,
    entropy=None,
    details=None,
):
    session = get_session()

    try:
        timestamp = datetime.now(timezone.utc).replace(tzinfo=None)

        alert = Alert(
            timestamp=timestamp,
            severity=severity,
            threat_score=threat_score,
            message=message,
            status="open",
        )

        incident = Incident(
            timestamp=timestamp,
            event_type=event_type,
            file_path=file_path,
            entropy=entropy,
            threat_score=threat_score,
            severity=severity,
            status="open",
            details=details or message,
        )

        session.add(alert)
        session.add(incident)

        session.commit()

        return {
            "alert_id": alert.id,
            "incident_id": incident.id,
            "threat_score": threat_score,
            "severity": severity,
            "message": message,
        }

    finally:
        session.close()


if __name__ == "__main__":
    result = create_alert_and_incident(
        threat_score=95,
        severity="Critical",
        message="Ransomware-like activity detected in sandbox.",
        event_type="suspicious_activity",
        file_path="data/sandbox/test.txt",
        details="Rapid modification, mass rename and high entropy indicators.",
    )

    print("[RDRS] Alert created successfully.")
    print(f"Alert ID: {result['alert_id']}")
    print(f"Incident ID: {result['incident_id']}")
    print(f"Threat Score: {result['threat_score']}")
    print(f"Severity: {result['severity']}")
