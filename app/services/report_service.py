import csv
import json
from pathlib import Path

from app.core.database import get_session, Alert, Incident, FileEvent


BASE_DIR = Path(__file__).resolve().parents[2]
REPORT_DIR = BASE_DIR / "data" / "reports"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def collect_report_data():
    session = get_session()

    try:
        alerts = session.query(Alert).order_by(Alert.timestamp.desc()).all()
        incidents = session.query(Incident).order_by(Incident.timestamp.desc()).all()
        events = session.query(FileEvent).order_by(FileEvent.timestamp.desc()).all()

        return {
            "alerts": [
                {
                    "id": alert.id,
                    "timestamp": str(alert.timestamp),
                    "severity": alert.severity,
                    "threat_score": alert.threat_score,
                    "message": alert.message,
                    "status": alert.status,
                }
                for alert in alerts
            ],

            "incidents": [
                {
                    "id": incident.id,
                    "timestamp": str(incident.timestamp),
                    "event_type": incident.event_type,
                    "file_path": incident.file_path,
                    "entropy": incident.entropy,
                    "threat_score": incident.threat_score,
                    "severity": incident.severity,
                    "status": incident.status,
                    "details": incident.details,
                }
                for incident in incidents
            ],

            "file_events": [
                {
                    "id": event.id,
                    "timestamp": str(event.timestamp),
                    "event_type": event.event_type,
                    "file_path": event.file_path,
                    "entropy": event.entropy,
                    "details": event.details,
                }
                for event in events
            ],
        }

    finally:
        session.close()


def generate_json_report():
    data = collect_report_data()

    output_file = REPORT_DIR / "rdrs_report.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    return output_file


def generate_csv_report():
    data = collect_report_data()

    output_file = REPORT_DIR / "rdrs_events.csv"

    rows = data["file_events"]

    fieldnames = [
        "id",
        "timestamp",
        "event_type",
        "file_path",
        "entropy",
        "details",
    ]

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)

    return output_file


if __name__ == "__main__":
    json_file = generate_json_report()
    csv_file = generate_csv_report()

    print("[RDRS] Reports generated successfully.")
    print(f"JSON Report: {json_file}")
    print(f"CSV Report: {csv_file}")
