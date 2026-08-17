"""In-process cache with stale-while-revalidate for expensive read aggregates.

The dashboard polls a handful of aggregate endpoints every 10-30s. On a table
with millions of rows those full-scan GROUP BYs cost seconds, yet the results
barely change second-to-second.

Strategy:
  * Fresh window  (age < ttl)          -> return cached value, no work.
  * Stale window  (ttl <= age < hard)  -> return cached value AND refresh in a
    background thread so the next caller gets fresh data. Nobody waits.
  * Expired/miss  (age >= hard | none) -> compute synchronously (first load).

Producers are no-arg callables that own their resources (e.g. open their own DB
session), because background refreshes run outside the request lifecycle.
Thread-safe: FastAPI runs sync endpoints in a threadpool.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class _Entry:
    ts: float
    value: Any


_lock = threading.Lock()
_store: dict[str, _Entry] = {}
_refreshing: set[str] = set()
_refresh_lock = threading.Lock()


def _spawn_refresh(key: str, producer: Callable[[], Any]) -> None:
    with _refresh_lock:
        if key in _refreshing:
            return  # a refresh for this key is already in flight
        _refreshing.add(key)

    def _run() -> None:
        try:
            value = producer()
            _store[key] = _Entry(time.monotonic(), value)
        except Exception as exc:  # noqa: BLE001 — keep serving stale on failure
            print(f"[cache] background refresh failed for {key!r}: {exc!r}")
        finally:
            with _refresh_lock:
                _refreshing.discard(key)

    threading.Thread(target=_run, name=f"cache-refresh:{key}", daemon=True).start()


def cached(
    key: str,
    ttl: float,
    producer: Callable[[], Any],
    stale_ttl: float | None = None,
) -> Any:
    """Return a cached value for `key`, recomputing via `producer` as needed.

    If `stale_ttl` is set, values older than `ttl` (but younger than
    `ttl + stale_ttl`) are served immediately while a background refresh runs.
    """
    now = time.monotonic()
    hit = _store.get(key)
    if hit is not None:
        age = now - hit.ts
        if age < ttl:
            return hit.value
        if stale_ttl is not None and age < ttl + stale_ttl:
            _spawn_refresh(key, producer)
            return hit.value

    # Expired or never computed: compute synchronously, de-duplicating callers.
    with _lock:
        hit = _store.get(key)
        if hit is not None and time.monotonic() - hit.ts < ttl:
            return hit.value
        value = producer()
        _store[key] = _Entry(time.monotonic(), value)
        return value


def prime(key: str, producer: Callable[[], Any]) -> None:
    """Populate a cache entry ahead of demand (startup pre-warm)."""
    try:
        _store[key] = _Entry(time.monotonic(), producer())
    except Exception as exc:  # noqa: BLE001
        print(f"[cache] prime failed for {key!r}: {exc!r}")


def invalidate(prefix: str | None = None) -> None:
    """Drop cached entries. With no prefix, clears everything."""
    with _lock:
        if prefix is None:
            _store.clear()
            return
        for k in [k for k in _store if k.startswith(prefix)]:
            _store.pop(k, None)
