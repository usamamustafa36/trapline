"use client";

import { LogOut } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

/** Clears the gate cookie server-side, then sends the browser back to the login page. */
export function SignOut() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  return (
    <button
      type="button"
      aria-busy={busy}
      title="Sign out"
      onClick={async () => {
        setBusy(true);
        await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
        router.replace("/login");
        router.refresh();
      }}
      className="mt-2 flex w-full min-h-[32px] items-center justify-center gap-2 rounded-xl border border-white/[0.06] bg-black/25 px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-wider text-dim transition-colors hover:border-white/[0.12] hover:text-fg disabled:opacity-50"
      disabled={busy}
    >
      <LogOut className="h-3.5 w-3.5" />
      {busy ? "Signing out" : "Sign out"}
    </button>
  );
}
