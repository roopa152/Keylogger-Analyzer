import winreg


STARTUP_REGISTRY_PATHS = [
    (
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "Current User",
    ),
    (
        winreg.HKEY_LOCAL_MACHINE,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "All Users",
    ),
]


SUSPICIOUS_KEYWORDS = [
    "keylogger",
    "key_log",
    "keystroke",
    "pynput",
    "password",
    "credential",
    "temp",
    "appdata\\local\\temp",
]


def classify_startup_entry(
    program_name: str,
    command: str,
) -> tuple[str, str]:
    combined_text = f"{program_name} {command}".lower()

    matched_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in combined_text
    ]

    if len(matched_keywords) >= 2:
        return (
            "High",
            f"Multiple suspicious indicators: {', '.join(matched_keywords)}",
        )

    if matched_keywords:
        return (
            "Medium",
            f"Matched suspicious indicator: {matched_keywords[0]}",
        )

    return (
        "Low",
        "Startup entry detected; no strong suspicious indicator.",
    )


def scan_startup_programs() -> list[dict]:
    startup_entries: list[dict] = []

    for root_key, registry_path, scope in STARTUP_REGISTRY_PATHS:
        try:
            key = winreg.OpenKey(
                root_key,
                registry_path,
                0,
                winreg.KEY_READ,
            )

            index = 0

            while True:
                try:
                    program_name, command, _ = winreg.EnumValue(
                        key,
                        index,
                    )

                    severity, reason = classify_startup_entry(
                        str(program_name),
                        str(command),
                    )

                    startup_entries.append(
                        {
                            "name": str(program_name),
                            "command": str(command),
                            "scope": scope,
                            "severity": severity,
                            "reason": reason,
                        }
                    )

                    index += 1

                except OSError:
                    break

            winreg.CloseKey(key)

        except PermissionError:
            continue

        except FileNotFoundError:
            continue

        except OSError:
            continue

    return startup_entries