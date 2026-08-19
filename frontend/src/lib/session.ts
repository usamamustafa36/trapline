/**
 * Session token used by the console gate.
 *
 * Runs in the edge runtime (middleware) as well as in route handlers, so it uses Web
 * Crypto rather than node:crypto and holds no state anywhere. The token is an expiry
 * plus an HMAC over that expiry, which is enough to make a cookie unforgeable without
 * a session store behind it.
 *
 * The secret and the credentials come from the environment. Nothing is compiled into
 * the client bundle, and a missing secret denies access rather than allowing it.
 */
const ENCODER = new TextEncoder();
const TTL_SECONDS = 12 * 60 * 60;

export const SESSION_COOKIE = "trapline_session";

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmac(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, ENCODER.encode(message));
  return b64url(new Uint8Array(sig));
}

/** Length-independent comparison, so a mismatch reveals nothing through timing. */
function constantTimeEqual(a: string, b: string): boolean {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i += 1) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

export function authConfig(): { user: string; password: string; secret: string } | null {
  const user = process.env.TRAPLINE_USER;
  const password = process.env.TRAPLINE_PASSWORD;
  const secret = process.env.TRAPLINE_AUTH_SECRET;
  // Fail closed. An unconfigured gate must not be an open one.
  if (!user || !password || !secret) return null;
  return { user, password, secret };
}

export async function checkCredentials(user: string, password: string): Promise<boolean> {
  const cfg = authConfig();
  if (!cfg) return false;
  // Compare digests rather than the raw values, so neither length nor content leaks.
  const [gotUser, wantUser, gotPass, wantPass] = await Promise.all([
    hmac(cfg.secret, `u:${user}`),
    hmac(cfg.secret, `u:${cfg.user}`),
    hmac(cfg.secret, `p:${password}`),
    hmac(cfg.secret, `p:${cfg.password}`),
  ]);
  return constantTimeEqual(gotUser, wantUser) && constantTimeEqual(gotPass, wantPass);
}

export async function issueToken(): Promise<string> {
  const cfg = authConfig();
  if (!cfg) throw new Error("auth is not configured");
  const exp = String(Math.floor(Date.now() / 1000) + TTL_SECONDS);
  return `${exp}.${await hmac(cfg.secret, `v1|${exp}`)}`;
}

export async function tokenIsValid(token: string | undefined): Promise<boolean> {
  const cfg = authConfig();
  if (!cfg || !token) return false;
  const dot = token.lastIndexOf(".");
  if (dot < 1) return false;
  const exp = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Math.floor(Date.now() / 1000)) return false;
  return constantTimeEqual(sig, await hmac(cfg.secret, `v1|${exp}`));
}

export const SESSION_MAX_AGE = TTL_SECONDS;
