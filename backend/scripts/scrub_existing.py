"""
Retro-scrub deployment identifiers out of events already in the database.

`import_dump` sanitises free text on the way in, but rows loaded before that fix
still carry the decoy page title and the sensors' real addresses. Doing that in
Python meant pulling every `raw_payload` across the wire, which does not finish at
eight million rows, so the rewrite runs server-side.

The patterns are **generated from `app.sanitise`** rather than retyped, so there is
still one definition of what an identifier is. `SQL_RULES` below is derived at import
time and `verify()` re-checks with the same regexes afterwards.

Idempotent: re-running finds nothing to change.

    python -m scripts.scrub_existing            # count only
    python -m scripts.scrub_existing --apply
"""
from __future__ import annotations

import argparse

from sqlalchemy import text

from app.database import SessionLocal
from app.sanitise import IP_MAP, ORG_PATTERNS

# Python regex -> Postgres ARE. Word boundaries are the only real difference.
def _to_pg(pattern: str) -> str:
    return pattern.replace(r"\b", r"\y")


SQL_RULES: list[tuple[str, str]] = [(_to_pg(ip.replace(".", r"\.")), repl) for ip, repl in IP_MAP.items()]
SQL_RULES += [(_to_pg(p.pattern), repl) for p, repl in ORG_PATTERNS]

# One combined predicate for "is this row still dirty".
DIRTY = "(" + "|".join(p for p, _ in SQL_RULES) + ")"

COLUMNS = ("payload_excerpt", "username_tried", "password_tried")


def _build_update() -> str:
    """Nest regexp_replace calls so all rules apply in one pass per column."""
    parts = []
    for col in COLUMNS:
        expr = col
        for pat, repl in SQL_RULES:
            expr = f"regexp_replace({expr}, $${pat}$$, $${repl}$$, 'gi')"
        parts.append(f"{col} = {expr}")
    expr = "raw_payload::text"
    for pat, repl in SQL_RULES:
        expr = f"regexp_replace({expr}, $${pat}$$, $${repl}$$, 'gi')"
    parts.append(f"raw_payload = cast({expr} as jsonb)")
    return "update events set " + ", ".join(parts) + f" where id between :lo and :hi and ({_dirty_pred()})"


def _dirty_pred() -> str:
    cols = " or ".join(f"{c} ~* $${DIRTY}$$" for c in COLUMNS)
    return f"{cols} or raw_payload::text ~* $${DIRTY}$$"


def count_dirty(db) -> int:
    return db.execute(text(f"select count(*) from events where {_dirty_pred()}")).scalar_one()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--batch", type=int, default=200_000, help="id-range width per statement")
    args = ap.parse_args()

    stmt = text(_build_update())
    with SessionLocal() as db:
        before = count_dirty(db)
        print(f"rows carrying an identifier: {before:,}")
        if not args.apply:
            print("dry run, nothing written. re-run with --apply")
            return
        if not before:
            print("nothing to do")
            return

        lo, hi = db.execute(text("select min(id), max(id) from events")).one()
        total = 0
        cur = lo
        while cur <= hi:
            end = min(cur + args.batch - 1, hi)
            res = db.execute(stmt, {"lo": cur, "hi": end})
            db.commit()
            total += res.rowcount or 0
            print(f"  ids {cur:,}-{end:,}  rewritten {total:,}", flush=True)
            cur = end + 1

        after = count_dirty(db)
        print(f"rewrote {total:,} row(s); {after:,} still dirty")
        if after:
            raise SystemExit("scrub incomplete, investigate before publishing")


if __name__ == "__main__":
    main()
