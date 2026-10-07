from __future__ import annotations

import json
from pathlib import Path

from .models import ActionEvent


def read_events(path: str | Path) -> list[ActionEvent]:
    events: list[ActionEvent] = []
    event_path = Path(path)
    if not event_path.exists():
        return events
    for line_number, line in enumerate(event_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            events.append(ActionEvent.model_validate(json.loads(line)))
        except Exception as exc:
            raise ValueError(f"Invalid event at {event_path}:{line_number}: {exc}") from exc
    return events
