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

from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402

WINDOWS = ["24h", "7d", "30d", "all"]
EVENTS_PAGE_SIZE = 14  # matches what the console requests
#: Per-address profiles are the only part of the snapshot that scales with the
#: dataset, so they are bounded. Everything else is a fixed set of aggregates.
MAX_ADDRESS_PROFILES = 400
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
    # This script runs the app in-process, so it reads DATASET_MODE from its own
    # environment, not from whatever a separate uvicorn was started with. Getting that
    # wrong once shipped a console that reported two of three sensors "offline" and
    # dropped the archived-dataset banner, which is the console claiming to be live.
    # Refuse rather than publish that.
    if not settings.dataset_mode:
        sys.exit(
            "DATASET_MODE is not set for this process.\n"
            "Without it the snapshot computes sensor status against the wall clock, so an\n"
            "archive looks like a dead live feed and the archived-dataset banner is absent.\n"
            "Re-run as: DATASET_MODE=true python scripts/capture_demo_snapshot.py"
        )

    out = Path(os.environ.get("SNAPSHOT_OUT", DEFAULT_OUT))
    client = TestClient(app)
    snapshot: dict[str, object] = {}
    misses: list[str] = []
    notes: list[str] = []

    def _note(msg: str) -> None:
        notes.append(msg)

    def grab_text(path: str, params: dict[str, object] | None = None) -> str | None:
        """Capture a non-JSON endpoint (YAML, CSV) as a plain string."""
        response = client.get(path, params=params)
        if response.status_code != 200:
            misses.append(f"{key_for(path, params)} -> HTTP {response.status_code}")
            return None
        snapshot[key_for(path, params)] = response.text
        return response.text

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

    # The reports view paginates at 50 and offers per-sensor scoping, so capture the
    # first few pages at that size. Without these the view falls back to a 14-row
    # page and the pager looks broken.
    for page in (1, 2, 3):
        grab("/api/v1/events", {"page_size": 50, "page": page})
    for alias in aliases:
        grab("/api/v1/events", {"page_size": 50, "page": 1, "vps": alias})

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

    # Cap per-address profiles. This is the only part of the snapshot that grows with
    # the dataset, so it is bounded to the addresses actually reachable from the UI:
    # the top-address lists, the cross-sensor view, and the event feed. Anything else
    # falls back gracefully in the route handler.
    capped = sorted(addresses)[:MAX_ADDRESS_PROFILES]
    for address in capped:
        grab(f"/api/v1/ips/{address}")
    if len(addresses) > len(capped):
        _note(f"address profiles capped at {len(capped)} of {len(addresses)}")

    # Analysis and generated detection content, which the Analysis and Detections
    # views depend on. These are single aggregate responses, so they add little size.
    grab("/api/v1/analysis/report")
    grab("/api/v1/analysis/overview")
    grab("/api/v1/analysis/coordination", {"limit": 40})
    grab("/api/v1/analysis/clients")
    grab("/api/v1/analysis/credentials")
    grab("/api/v1/analysis/guessing")
    grab("/api/v1/analysis/commands")
    grab("/api/v1/analysis/rhythm")
    grab("/api/v1/analysis/http")
    grab("/api/v1/detections/sigma")
    grab("/api/v1/detections/blocklist")
    grab("/api/v1/detections/stix")

    # Text/file downloads. These return YAML and CSV rather than JSON, so they are
    # stored as strings; the route handler serves a string body verbatim with a
    # content type inferred from the path. Without these the download buttons 404.
    grab_text("/api/v1/detections/sigma.yml")
    # /export/events.csv is deliberately NOT captured. The full export of a
    # 200k-event dataset is ~23 MB, which would multiply the snapshot tenfold, and
    # nothing in the console links to it: the report builder writes CSV client-side
    # from the rows already on screen. Against a live backend the endpoint still
    # streams normally.

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, indent=1, default=str), encoding="utf-8")

    size_kb = out.stat().st_size / 1024
    print(f"[snapshot] {len(snapshot)} response(s) captured")
    print(f"[snapshot] {len(aliases)} sensor(s), {len(addresses)} address profile(s)")
    print(f"[snapshot] written to {out} ({size_kb:.0f} KB)")
    for n in notes:
        print(f"[snapshot] {n}")
    if misses:
        print(f"[snapshot] {len(misses)} endpoint(s) did not return 200:")
        for miss in misses:
            print(f"             {miss}")


if __name__ == "__main__":
    main()
