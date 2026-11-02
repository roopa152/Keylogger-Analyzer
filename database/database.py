import sqlite3
from datetime import datetime
from pathlib import Path


DATABASE_PATH = Path("database/keylogger_analyzer.db")


def get_connection() -> sqlite3.Connection:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at TEXT NOT NULL,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )


def save_detection(process: dict) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO detections (
                detected_at,
                pid,
                process_name,
                severity,
                reason,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                int(process["pid"]),
                str(process["name"]),
                str(process["severity"]),
                str(process["reason"]),
                str(process["status"]),
            ),
        )


def get_detection_history() -> list[dict]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                detected_at,
                pid,
                process_name,
                severity,
                reason,
                status
            FROM detections
            ORDER BY id DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]