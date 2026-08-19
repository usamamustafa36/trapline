import { NextResponse } from "next/server";

import {
  SESSION_COOKIE,
  SESSION_MAX_AGE,
  authConfig,
  checkCredentials,
  issueToken,
  publicMode,
} from "@/lib/session";

/** Deliberately vague on failure: it never says which of the two was wrong. */
export async function POST(request: Request): Promise<NextResponse> {
  if (publicMode()) {
    return NextResponse.json({ detail: "This deployment has no console gate." }, { status: 404 });
  }

  if (!authConfig()) {
    return NextResponse.json(
      { detail: "Console gate is not configured on this deployment." },
      { status: 503 },
    );
  }

  let user = "";
  let password = "";
  try {
    const body = await request.json();
    user = typeof body?.user === "string" ? body.user : "";
    password = typeof body?.password === "string" ? body.password : "";
  } catch {
    return NextResponse.json({ detail: "Malformed request." }, { status: 400 });
  }

  if (!(await checkCredentials(user, password))) {
    return NextResponse.json({ detail: "Those credentials were not accepted." }, { status: 401 });
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set({
    name: SESSION_COOKIE,
    value: await issueToken(),
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_MAX_AGE,
  });
  return response;
}
