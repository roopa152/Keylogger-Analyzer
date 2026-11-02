from pathlib import Path


WHITELIST_FILE = Path("database/whitelist.txt")


def ensure_whitelist_file() -> None:
    WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not WHITELIST_FILE.exists():
        WHITELIST_FILE.write_text("", encoding="utf-8")


def load_whitelist() -> set[str]:
    ensure_whitelist_file()

    entries = WHITELIST_FILE.read_text(
        encoding="utf-8"
    ).splitlines()

    return {
        entry.strip().lower()
        for entry in entries
        if entry.strip()
    }


def add_to_whitelist(process_name: str) -> bool:
    process_name = process_name.strip().lower()

    if not process_name:
        return False

    whitelist = load_whitelist()

    if process_name in whitelist:
        return False

    with WHITELIST_FILE.open("a", encoding="utf-8") as file:
        file.write(process_name + "\n")

    return True


def is_whitelisted(process_name: str) -> bool:
    return process_name.strip().lower() in load_whitelist()