"use client";

/**
 * Console gate.
 *
 * Credentials are checked in `/api/auth/login`, never here, so nothing about them
 * reaches the client bundle. The form only carries the answer back.
 */
import { Lock, Loader2 } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { ProjectLogo } from "@/components/ui/VpsLogo";

export default function LoginPage() {
  const router = useRouter();
  const params = useSearchParams();
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, password }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.detail ?? "Sign in failed.");
        setBusy(false);
        return;
      }
      const next = params.get("next");
      // Only ever return to a path on this origin.
      router.replace(next && next.startsWith("/") && !next.startsWith("//") ? next : "/");
    } catch {
      setError("Could not reach the server.");
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-void px-5 py-10">
      <div className="w-full max-w-[360px]">
        <div className="mb-6 flex items-center gap-3">
          <ProjectLogo />
          <div>
            <div className="font-display text-[15px] font-semibold text-fg">Trapline</div>
            <div className="hud-label">Honeynet telemetry console</div>
          </div>
        </div>

        <form onSubmit={submit} className="panel flex flex-col gap-3 p-5">
          <div>
            <label htmlFor="user" className="hud-label mb-1 block">
              Username
            </label>
            <input
              id="user"
              name="username"
              autoComplete="username"
              value={user}
              onChange={(e) => setUser(e.target.value)}
              required
              autoFocus
              className="w-full rounded border border-line bg-panel px-2.5 py-2 font-mono text-[13px] text-fg placeholder:text-muted focus:border-signal/50 focus:outline-none"
            />
          </div>
          <div>
            <label htmlFor="password" className="hud-label mb-1 block">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full rounded border border-line bg-panel px-2.5 py-2 font-mono text-[13px] text-fg placeholder:text-muted focus:border-signal/50 focus:outline-none"
            />
          </div>

          <button
            type="submit"
            disabled={busy || !user || !password}
            aria-busy={busy}
            className="mt-1 inline-flex min-h-[38px] items-center justify-center gap-2 rounded border border-signal/50 bg-signal/15 py-2 font-mono text-[12px] font-semibold uppercase tracking-wider text-signal transition-colors hover:bg-signal/25 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busy ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Signing in
              </>
            ) : (
              <>
                <Lock className="h-4 w-4" /> Sign in
              </>
            )}
          </button>

          <p role="alert" aria-live="polite" className="min-h-[16px] font-mono text-[11px] text-hostile-soft">
            {error ?? ""}
          </p>
        </form>

        <p className="mt-4 font-mono text-[10.5px] leading-relaxed text-muted">
          This console serves an archived capture. Sensor locations and operator names are
          not present in the data.
        </p>
      </div>
    </main>
  );
}
