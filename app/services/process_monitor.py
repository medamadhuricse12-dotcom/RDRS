import psutil
from datetime import datetime, timezone

from app.core.database import get_session, Process


def collect_processes():
    processes = []

    for proc in psutil.process_iter(
        ["pid", "name", "cpu_percent", "memory_percent", "exe", "ppid"]
    ):
        try:
            info = proc.info

            processes.append({
                "timestamp": datetime.now(timezone.utc),
                "pid": info.get("pid"),
                "name": info.get("name") or "unknown",
                "cpu_percent": info.get("cpu_percent") or 0.0,
                "memory_percent": info.get("memory_percent") or 0.0,
                "exe_path": info.get("exe"),
                "parent_pid": info.get("ppid"),
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    return processes


def save_processes(processes):
    session = get_session()

    try:
        for process in processes:
            record = Process(
                timestamp=process["timestamp"],
                pid=process["pid"],
                name=process["name"],
                cpu_percent=process["cpu_percent"],
                memory_percent=process["memory_percent"],
                exe_path=process["exe_path"],
                parent_pid=process["parent_pid"],
            )

            session.add(record)

        session.commit()

    finally:
        session.close()


def get_process_snapshot():
    processes = collect_processes()
    save_processes(processes)
    return processes


if __name__ == "__main__":
    processes = get_process_snapshot()

    print(f"[RDRS] Processes detected: {len(processes)}")
    print("[RDRS] Process records saved to SQLite database.")

    for process in processes[:10]:
        print(
            f"PID={process['pid']} | "
            f"Name={process['name']} | "
            f"CPU={process['cpu_percent']}% | "
            f"Memory={process['memory_percent']}%"
        )
