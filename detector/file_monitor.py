from datetime import datetime
from pathlib import Path
from queue import Queue

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


SUSPICIOUS_NAMES = [
    "keylog",
    "keystroke",
    "keyboard_log",
    "password",
    "credential",
]

SUSPICIOUS_EXTENSIONS = {
    ".log",
    ".txt",
    ".dat",
}


class SuspiciousFileHandler(FileSystemEventHandler):
    def __init__(self, event_queue: Queue) -> None:
        super().__init__()
        self.event_queue = event_queue

    def on_created(self, event) -> None:
        if not event.is_directory:
            self.analyze_file(event.src_path, "Created")

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self.analyze_file(event.src_path, "Modified")

    def analyze_file(self, file_path: str, action: str) -> None:
        path = Path(file_path)
        file_name = path.name.lower()
        extension = path.suffix.lower()

        matched_name = next(
            (
                keyword
                for keyword in SUSPICIOUS_NAMES
                if keyword in file_name
            ),
            None,
        )

        if matched_name:
            severity = "High"
            reason = (
                f"Suspicious filename matched indicator: {matched_name}"
            )
        elif extension in SUSPICIOUS_EXTENSIONS:
            severity = "Medium"
            reason = (
                f"Monitored file extension detected: {extension}"
            )
        else:
            return

        self.event_queue.put(
            {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": action,
                "file": str(path),
                "severity": severity,
                "reason": reason,
            }
        )


class FileMonitor:
    def __init__(
        self,
        folder: str,
        event_queue: Queue,
    ) -> None:
        self.folder = Path(folder)
        self.event_queue = event_queue
        self.observer: Observer | None = None

    def start(self) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)

        handler = SuspiciousFileHandler(self.event_queue)

        self.observer = Observer()
        self.observer.schedule(
            handler,
            str(self.folder),
            recursive=True,
        )
        self.observer.start()

    def stop(self) -> None:
        if self.observer is None:
            return

        self.observer.stop()
        self.observer.join(timeout=3)
        self.observer = None