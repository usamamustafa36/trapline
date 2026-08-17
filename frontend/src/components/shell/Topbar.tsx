"use client";

import { useQuery } from "@tanstack/react-query";
import { Search, Clock } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

function useUtcClock() {
  const [now, setNow] = useState<Date | null>(null);
  useEffect(() => {
    setNow(new Date());
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

export function Topbar() {
  const router = useRouter();
  const [q, setQ] = useState("");
  const now = useUtcClock();
  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 10_000,
    retry: false,
  });

  const link = health ? "online" : "degraded";
  const utc = now
    ? now.toISOString().slice(11, 19)
    : "--:--:--";

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const v = q.trim();
    if (v) router.push(`/ips/${encodeURIComponent(v)}`);
  }

  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-white/[0.05] bg-base/70 px-5 backdrop-blur-xl lg:px-7">
      <form onSubmit={submit} className="relative w-full max-w-md">
        <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search IP or indicator…"
          className="w-full rounded-full border border-white/[0.08] bg-white/[0.03] py-2.5 pl-10 pr-4 font-mono text-[12px] tracking-wide text-fg placeholder:text-muted transition-colors focus:border-signal/50 focus:bg-white/[0.05] focus:outline-none focus:ring-2 focus:ring-signal/20"
        />
      </form>

      <div className="ml-auto flex items-center gap-2.5">
        <div className="hidden items-center gap-2 rounded-full border border-white/[0.07] bg-white/[0.03] py-1.5 pl-2.5 pr-3.5 md:flex">
          <span className="relative flex h-2 w-2">
            <span
              className={cn(
                "absolute inline-flex h-full w-full rounded-full opacity-60",
                health ? "animate-ping bg-ops" : "bg-hostile",
              )}
            />
            <span
              className={cn(
                "relative inline-flex h-2 w-2 rounded-full",
                health ? "bg-ops" : "bg-hostile",
              )}
            />
          </span>
          <div className="leading-none">
            <div className="hud-label !text-[8.5px]">API</div>
            <div
              className={cn(
                "font-mono text-[11px] font-semibold uppercase",
                health ? "text-ops" : "text-hostile-soft",
              )}
            >
              {link}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 rounded-full border border-white/[0.07] bg-white/[0.03] py-1.5 pl-2.5 pr-3.5">
          <Clock className="h-4 w-4 text-signal/80" />
          <div className="leading-none">
            <div className="hud-label !text-[8.5px]">UTC</div>
            <div className="tabular font-mono text-[13px] font-semibold text-fg">{utc}</div>
          </div>
        </div>
      </div>
    </header>
  );
}
