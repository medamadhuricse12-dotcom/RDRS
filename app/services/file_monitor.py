from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from app.core.database import get_session, FileEvent
from app.core.detector import analyze_file


class RDRSEventHandler(FileSystemEventHandler):

    def _record(self, event_type, file_path):
        path = Path(file_path)

        if not path.is_file():
            return

        result = analyze_file(str(path))

        session = get_session()

        try:
            event = FileEvent(
                event_type=event_type,
                file_path=str(path),
                entropy=result["entropy"],
                details=str(result),
            )

            session.add(event)
            session.commit()

            print(
                f"[RDRS] {event_type}: {path} | "
                f"Entropy={result['entropy']} | "
                f"Score={result['threat_score']}"
            )
        finally:
            session.close()

    def on_created(self, event):
        if not event.is_directory:
            self._record("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._record("modified", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._record("renamed", event.dest_path)


def start_monitor(path="data/sandbox", recursive=True):
    Path(path).mkdir(parents=True, exist_ok=True)

    observer = Observer()
    observer.schedule(
        RDRSEventHandler(),
        path,
        recursive=recursive,
    )

    observer.start()

    print(f"[RDRS] Monitoring: {Path(path).resolve()}")

    return observer
