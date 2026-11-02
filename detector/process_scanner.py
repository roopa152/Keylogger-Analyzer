import psutil

from detector.whitelist import is_whitelisted


LOW_KEYWORDS = [
    "keyboard",
    "logger",
]

MEDIUM_KEYWORDS = [
    "keystroke",
    "key_log",
    "keyboard_logger",
]

HIGH_KEYWORDS = [
    "keylogger",
    "pynput",
    "hookkeyboard",
]

CRITICAL_KEYWORDS = [
    "credential_stealer",
    "password_stealer",
    "remote_keylogger",
]


def classify_severity(combined_text: str) -> tuple[str | None, str | None]:
    """Return severity and matched keyword."""

    for keyword in CRITICAL_KEYWORDS:
        if keyword in combined_text:
            return "Critical", keyword

    for keyword in HIGH_KEYWORDS:
        if keyword in combined_text:
            return "High", keyword

    for keyword in MEDIUM_KEYWORDS:
        if keyword in combined_text:
            return "Medium", keyword

    for keyword in LOW_KEYWORDS:
        if keyword in combined_text:
            return "Low", keyword

    return None, None


def scan_processes() -> tuple[int, list[dict]]:
    """Scan running processes for suspicious indicators."""

    total_processes = 0
    suspicious_processes: list[dict] = []

    for process in psutil.process_iter(
        ["pid", "name", "exe", "cmdline"]
    ):
        total_processes += 1

        try:
            process_info = process.info

            process_name = process_info.get("name") or "Unknown"

            if is_whitelisted(process_name):
                continue

            command_line = process_info.get("cmdline") or []
            executable_path = process_info.get("exe") or ""

            combined_text = " ".join(
                [
                    process_name,
                    executable_path,
                    " ".join(command_line),
                ]
            ).lower()

            severity, matched_keyword = classify_severity(
                combined_text
            )

            if severity and matched_keyword:
                suspicious_processes.append(
                    {
                        "pid": process_info["pid"],
                        "name": process_name,
                        "severity": severity,
                        "reason": (
                            f"Matched suspicious indicator: "
                            f"{matched_keyword}"
                        ),
                        "status": "Detected",
                    }
                )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    return total_processes, suspicious_processes


def terminate_process(pid: int) -> tuple[bool, str]:
    """Safely terminate a selected process by PID."""

    try:
        process = psutil.Process(pid)
        process_name = process.name()

        process.terminate()
        process.wait(timeout=5)

        return True, f"{process_name} (PID {pid}) was terminated."

    except psutil.NoSuchProcess:
        return False, "The selected process no longer exists."

    except psutil.AccessDenied:
        return False, (
            "Access denied. Try running the analyzer as administrator."
        )

    except psutil.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=3)

            return True, (
                f"Process PID {pid} was forcefully stopped."
            )

        except Exception as error:
            return False, (
                f"Unable to stop the process: {error}"
            )

    except Exception as error:
        return False, f"Termination failed: {error}"