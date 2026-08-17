"""
Capture a demo snapshot of every read endpoint the console actually calls.

Writes a single JSON map of "path?sorted-query" -> response body, which the
frontend serves from its own Next.js route handler. That lets the console be
deployed on its own, fully populated, with no backend and no database behind it.

The responses are captured from the real API running against a real database, so
the shapes cannot drift from what the components expect. Regenerate whenever the
dataset changes:

    DATABASE_URL=... python -m scripts.capture_demo_snapshot

Run it after loading data with `app.import_csv`. The output path defaults to the
frontend's bundled snapshot.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.parse import urlencode

# Import the app package from the backend root regardless of where this is run.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

WINDOWS = ["24h", "7d", "30d", "all"]
EVENTS_PAGE_SIZE = 14  # matches what the console requests
DEFAULT_OUT = (
    Path(__file__).resolve().parents[2] / "frontend" / "src" / "demo-snapshot.json"
)


def key_for(path: str, params: dict[str, object] | None = None) -> str:
    """Canonical snapshot key: path plus query sorted by name."""
    if not params:
        return path
    items = sorted((k, str(v)) for k, v in params.items() if v is not None and v != "")
    return f"{path}?{urlencode(items)}" if items else path


def main() -> None:
    out = Path(os.environ.get("SNAPSHOT_OUT", DEFAULT_OUT))
    client = TestClient(app)
    snapshot: dict[str, object] = {}
    misses: list[str] = []

    def grab(path: str, params: dict[str, object] | None = None) -> object | None:
        response = client.get(path, params=params)
        if response.status_code != 200:
            misses.append(f"{key_for(path, params)} -> HTTP {response.status_code}")
            return None
        body = response.json()
        snapshot[key_for(path, params)] = body
        return body

    grab("/api/v1/health")

    sensors = grab("/api/v1/vps") or []
    aliases = [s["alias"] for s in sensors if isinstance(s, dict) and "alias" in s]

    for window in WINDOWS:
        grab("/api/v1/stats/overview", {"window": window})
        for alias in aliases:
            grab(f"/api/v1/stats/{alias}", {"window": window})

    # Unfiltered event feed, plus the per-sensor scoping the console offers.
    grab("/api/v1/events", {"page_size": EVENTS_PAGE_SIZE})
    for alias in aliases:
        grab("/api/v1/events", {"vps": alias, "page_size": EVENTS_PAGE_SIZE})

    # A deeper page of events so the reports view has something to work with.
    grab("/api/v1/events", {"page_size": 200})

    cross = grab("/api/v1/ips/cross-vps", {"min_vps": 2}) or []

    # Every address in the dataset gets a profile, so drill-down always resolves.
    addresses: set[str] = set()
    for row in cross if isinstance(cross, list) else []:
        if isinstance(row, dict) and row.get("ip"):
            addresses.add(str(row["ip"]))
    feed = snapshot.get(key_for("/api/v1/events", {"page_size": 200}))
    if isinstance(feed, dict):
        for event in feed.get("items", []) or []:
            if isinstance(event, dict) and event.get("src_ip"):
                addresses.add(str(event["src_ip"]))

    for address in sorted(addresses):
        grab(f"/api/v1/ips/{address}")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, indent=1, default=str), encoding="utf-8")

    size_kb = out.stat().st_size / 1024
    print(f"[snapshot] {len(snapshot)} response(s) captured")
    print(f"[snapshot] {len(aliases)} sensor(s), {len(addresses)} address profile(s)")
    print(f"[snapshot] written to {out} ({size_kb:.0f} KB)")
    if misses:
        print(f"[snapshot] {len(misses)} endpoint(s) did not return 200:")
        for miss in misses:
            print(f"             {miss}")


if __name__ == "__main__":
    main()
