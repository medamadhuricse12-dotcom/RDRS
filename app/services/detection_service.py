from app.core.window import analyze_window
from app.core.detector import analyze_window_result
from app.services.alert_service import create_alert_and_incident


def run_detection(window_seconds=60):
    # Get recent file activity
    window_result = analyze_window(window_seconds)

    # Analyze activity for ransomware-like indicators
    detection_result = analyze_window_result(window_result)

    score = detection_result["threat_score"]
    severity = detection_result["severity"]

    # Create alert and incident only when activity is suspicious
    if score >= 40:
        message = (
            f"Suspicious activity detected. "
            f"Threat score: {score}. "
            f"Modified files: {window_result['modified_files']}, "
            f"Renamed files: {window_result['renamed_files']}, "
            f"High entropy files: {window_result['high_entropy_files']}."
        )

        result = create_alert_and_incident(
            threat_score=score,
            severity=severity,
            message=message,
            event_type="ransomware_like_activity",
            details=str({
                "window": window_result,
                "detection": detection_result,
            }),
        )

        return {
            "window": window_result,
            "detection": detection_result,
            "alert": result,
        }

    return {
        "window": window_result,
        "detection": detection_result,
        "alert": None,
    }


if __name__ == "__main__":
    result = run_detection(60)

    print("[RDRS] Automatic Detection")
    print(f"Threat Score: {result['detection']['threat_score']}")
    print(f"Severity: {result['detection']['severity']}")

    if result["alert"]:
        print("[RDRS] Alert and incident created.")
        print(f"Alert ID: {result['alert']['alert_id']}")
        print(f"Incident ID: {result['alert']['incident_id']}")
    else:
        print("[RDRS] No suspicious activity detected.")
