/**
 * Read-only API served from a bundled snapshot.
 *
 * Lets the console be deployed on its own, fully populated, with no backend and
 * no database behind it. Responses in `demo-snapshot.json` were captured from
 * the real FastAPI service running against a real database
 * (`backend/scripts/capture_demo_snapshot.py`), so their shapes cannot drift
 * from what the components expect.
 *
 * Point the console at itself to use this:
 *     NEXT_PUBLIC_API_BASE=/api/v1
 *
 * Leave that variable pointing at a real deployment and these handlers are
 * simply never reached.
 */
import { NextResponse } from "next/server";

import snapshot from "@/demo-snapshot.json";

const RESPONSES = snapshot as Record<string, unknown>;
const PREFIX = "/api/v1";

/** Canonical key: path plus query sorted by name. Mirrors the capture script. */
function keyFor(path: string, query: URLSearchParams): string {
  const items = [...query.entries()]
    .filter(([, value]) => value !== "" && value !== "undefined" && value !== "null")
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  if (items.length === 0) return path;
  const encoded = items.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  return `${path}?${encoded.join("&")}`;
}

/**
 * Exact match first, then progressively looser fallbacks, so a filter
 * combination that was never captured degrades to the nearest sensible
 * response instead of erroring in the UI.
 */
function lookup(path: string, query: URLSearchParams): unknown | undefined {
  const exact = RESPONSES[keyFor(path, query)];
  if (exact !== undefined) return exact;

  // Drop one parameter at a time, least significant first.
  const droppable = ["page", "q", "protocol", "event_type", "severity", "since", "until"];
  const reduced = new URLSearchParams(query);
  for (const name of droppable) {
    if (reduced.has(name)) {
      reduced.delete(name);
      const hit = RESPONSES[keyFor(path, reduced)];
      if (hit !== undefined) return hit;
    }
  }

  // Then the bare path.
  const bare = RESPONSES[path];
  if (bare !== undefined) return bare;

  // Finally, any captured variant of this path at all.
  const prefix = `${path}?`;
  const firstVariant = Object.keys(RESPONSES).find((k) => k.startsWith(prefix));
  return firstVariant ? RESPONSES[firstVariant] : undefined;
}

export async function GET(
  request: Request,
  { params }: { params: { path: string[] } },
): Promise<NextResponse> {
  const path = `${PREFIX}/${(params.path ?? []).join("/")}`;
  const query = new URL(request.url).searchParams;

  const body = lookup(path, query);
  if (body === undefined) {
    return NextResponse.json(
      { detail: `No snapshot data for ${path}` },
      { status: 404 },
    );
  }

  return NextResponse.json(body, {
    headers: { "Cache-Control": "public, max-age=60, stale-while-revalidate=600" },
  });
}

/** Sensor registration writes state, which a snapshot cannot do. Say so plainly. */
export async function POST(): Promise<NextResponse> {
  return NextResponse.json(
    { detail: "This console is running on a read-only dataset. Registration is disabled." },
    { status: 501 },
  );
}
