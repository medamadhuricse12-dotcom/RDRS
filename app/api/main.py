from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.core.database import init_db, get_session, FileEvent, Alert, Incident
from app.core.window import analyze_window
from app.core.detector import analyze_window_result
from app.services.file_monitor import start_monitor
from app.services.detection_service import run_detection
from app.services.response_service import simulate_response


BASE_DIR = Path(__file__).resolve().parents[2]


@asynccontextmanager
async def lifespan(app):
    # Create SQLite database tables on startup
    init_db()

    observer = start_monitor(
        str(BASE_DIR / "data" / "sandbox"),
        recursive=True,
    )

    yield

    observer.stop()
    observer.join()


app = FastAPI(
    title="RDRS API",
    description="Ransomware Detection and Response System",
    version="1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "RDRS API",
    }


@app.get("/status")
def status():
    window = analyze_window(60)
    detection = analyze_window_result(window)

    return {
        "status": "running",
        "window_seconds": 60,
        "recent_events": window["total_events"],
        "modified_files": window["modified_files"],
        "renamed_files": window["renamed_files"],
        "high_entropy_files": window["high_entropy_files"],
        "threat_score": detection["threat_score"],
        "severity": detection["severity"],
    }


@app.get("/alerts")
def alerts():
    session = get_session()

    try:
        records = (
            session.query(Alert)
            .order_by(Alert.timestamp.desc())
            .all()
        )

        return [
            {
                "id": alert.id,
                "timestamp": alert.timestamp,
                "severity": alert.severity,
                "threat_score": alert.threat_score,
                "message": alert.message,
                "status": alert.status,
            }
            for alert in records
        ]

    finally:
        session.close()


@app.get("/events")
def events():
    session = get_session()

    try:
        records = (
            session.query(FileEvent)
            .order_by(FileEvent.timestamp.desc())
            .limit(100)
            .all()
        )

        return [
            {
                "id": event.id,
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "file_path": event.file_path,
                "entropy": event.entropy,
                "details": event.details,
            }
            for event in records
        ]

    finally:
        session.close()


@app.get("/reports")
def reports():
    session = get_session()

    try:
        incidents = session.query(Incident).count()
        alerts_count = session.query(Alert).count()
        events_count = session.query(FileEvent).count()

        return {
            "incidents": incidents,
            "alerts": alerts_count,
            "file_events": events_count,
        }

    finally:
        session.close()


@app.post("/scan")
def scan():
    result = run_detection()
    return {
        "success": True,
        "result": result,
    }


@app.post("/settings")
def settings():
    return {
        "simulation_mode": True,
        "window_seconds": 60,
        "monitor_path": str(BASE_DIR / "data" / "sandbox"),
    }


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    dashboard_path = BASE_DIR / "templates" / "dashboard.html"

    return dashboard_path.read_text(encoding="utf-8")
