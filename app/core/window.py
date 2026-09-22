from datetime import datetime, timezone, timedelta

from app.core.database import get_session, FileEvent


def get_recent_events(window_seconds=60):
    session = get_session()

    try:
        cutoff_time = (
            datetime.now(timezone.utc).replace(tzinfo=None)
            - timedelta(seconds=window_seconds)
        )

        events = (
            session.query(FileEvent)
            .filter(FileEvent.timestamp >= cutoff_time)
            .order_by(FileEvent.timestamp.desc())
            .all()
        )

        return events

    finally:
        session.close()


def analyze_window(window_seconds=60):
    events = get_recent_events(window_seconds)

    modified_files = 0
    renamed_files = 0
    high_entropy_files = 0

    for event in events:
        if event.event_type == "modified":
            modified_files += 1

        elif event.event_type == "renamed":
            renamed_files += 1

        if event.entropy is not None and event.entropy >= 7.0:
            high_entropy_files += 1

    return {
        "window_seconds": window_seconds,
        "total_events": len(events),
        "modified_files": modified_files,
        "renamed_files": renamed_files,
        "high_entropy_files": high_entropy_files,
    }


if __name__ == "__main__":
    result = analyze_window(60)

    print("[RDRS] Sliding Window Analysis")
    print(f"Window: {result['window_seconds']} seconds")
    print(f"Total events: {result['total_events']}")
    print(f"Modified files: {result['modified_files']}")
    print(f"Renamed files: {result['renamed_files']}")
    print(f"High entropy files: {result['high_entropy_files']}")
