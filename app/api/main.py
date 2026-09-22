from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse

from app.core.database import get_session, Alert, FileEvent, Incident
from app.core.window import analyze_window
from app.services.detection_service import run_detection
from app.services.file_monitor import start_monitor


BASE_DIR = Path(__file__).resolve().parents[2]


@asynccontextmanager
async def lifespan(app):
    monitor_observer = start_monitor(
        path=str(BASE_DIR / "data" / "sandbox"),
        recursive=True,
    )

    yield

    monitor_observer.stop()
    monitor_observer.join()


app = FastAPI(
    title="RDRS API",
    description="Ransomware Detection and Response System API",
    version="1.0.0",
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

    return {
        "status": "running",
        "monitor_path": str(BASE_DIR / "data" / "sandbox"),
        "window_seconds": 60,
        "recent_events": window["total_events"],
        "modified_files": window["modified_files"],
        "renamed_files": window["renamed_files"],
        "high_entropy_files": window["high_entropy_files"],
    }


@app.get("/alerts")
def alerts():
    session = get_session()

    try:
        records = (
            session.query(Alert)
            .order_by(Alert.timestamp.desc())
            .limit(50)
            .all()
        )

        return [
            {
                "id": alert.id,
                "timestamp": str(alert.timestamp),
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
                "timestamp": str(event.timestamp),
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
        alert_count = session.query(Alert).count()
        incident_count = session.query(Incident).count()
        event_count = session.query(FileEvent).count()

        return {
            "alerts": alert_count,
            "incidents": incident_count,
            "file_events": event_count,
        }

    finally:
        session.close()


@app.post("/scan")
def scan():
    result = run_detection(60)

    return {
        "message": "Detection scan completed.",
        "result": result,
    }


@app.post("/settings")
def settings(settings_data: dict):
    return JSONResponse(
        content={
            "message": "Settings received.",
            "settings": settings_data,
        }
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    dashboard_path = BASE_DIR / "templates" / "dashboard.html"

    return dashboard_path.read_text(encoding="utf-8")
