from datetime import datetime
from random import choice


SAMPLE_KEYS = [
    ("A", "Pressed"),
    ("B", "Pressed"),
    ("Enter", "Pressed"),
    ("Backspace", "Pressed"),
    ("Ctrl+C", "Shortcut"),
    ("Ctrl+V", "Shortcut"),
    ("Shift", "Modifier"),
    ("Caps Lock", "Modifier"),
    ("Tab", "Pressed"),
    ("Esc", "Pressed"),
]


def generate_sample_keyboard_events(count: int = 15) -> list[dict]:
    """Generate harmless sample keyboard events for demonstration."""

    events: list[dict] = []

    for _ in range(count):
        key, event_type = choice(SAMPLE_KEYS)

        events.append(
            {
                "time": datetime.now().strftime("%H:%M:%S"),
                "key": key,
                "event": event_type,
            }
        )

    return events