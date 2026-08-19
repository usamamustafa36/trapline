/**
 * Console gate.
 *
 * The published console is a static frontend serving a captured snapshot, so a login
 * built in React would be decorative: the snapshot routes under `/api/v1` stay
 * fetchable and the password ends up in the client bundle. Middleware runs on the
 * server before either is reached, so the gate goes here instead.
 *
 * TRAPLINE_PUBLIC=true removes the gate for a snapshot-only deployment. It is ignored
 * whenever credentials are configured, so it cannot open a console serving live data.
 * Note the flag and the credentials are both read at build time in the edge bundle, so
 * changing either needs a redeploy, not just a dashboard edit.
 *
 * Requires Next 14.2.25 or later. Earlier releases accept an `x-middleware-subrequest`
 * header that skips middleware entirely (CVE-2025-29927), which would make this
 * bypassable with one header. This project is on 14.2.35.
 */
import { NextRequest, NextResponse } from "next/server";

import { SESSION_COOKIE, authConfig, publicMode, tokenIsValid } from "@/lib/session";

const PUBLIC_PATHS = ["/login", "/api/auth/login", "/api/auth/logout"];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Opted-in public deployment: no gate at all.
  if (publicMode()) {
    // A stale /login link would otherwise render a form that cannot succeed.
    if (pathname === "/login") {
      const home = request.nextUrl.clone();
      home.pathname = "/";
      home.search = "";
      return NextResponse.redirect(home);
    }
    return NextResponse.next();
  }

  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    return NextResponse.next();
  }

  if (await tokenIsValid(request.cookies.get(SESSION_COOKIE)?.value)) {
    return NextResponse.next();
  }

  // Data routes get a status, not a redirect, so a fetch fails cleanly instead of
  // parsing an HTML login page as JSON.
  if (pathname.startsWith("/api/")) {
    return NextResponse.json(
      { detail: authConfig() ? "Authentication required." : "Console gate is not configured." },
      { status: 401, headers: { "Cache-Control": "no-store" } },
    );
  }

  const login = request.nextUrl.clone();
  login.pathname = "/login";
  login.search = "";
  // Send them back where they were aiming once they are through.
  if (pathname !== "/") login.searchParams.set("next", pathname);
  return NextResponse.redirect(login);
}

export const config = {
  // Everything except Next's own assets and the icons a browser fetches unauthenticated.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg|apple-icon.png|robots.txt).*)"],
};
