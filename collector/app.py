from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request


app = Flask(__name__)
RESULTS = Path(os.getenv("RESULTS_DIR", "/results"))
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
LOCK = threading.Lock()


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/events")
def events():
    event = request.get_json(force=True)
    run_id = str(event.get("run_id", ""))
    if not RUN_ID.fullmatch(run_id):
        return jsonify(error="invalid run_id"), 400
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    run_dir = RESULTS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    with LOCK, (run_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    return jsonify(status="recorded"), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
