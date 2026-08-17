"use client";

/**
 * Archived-dataset notice.
 *
 * When the console is serving a historical capture rather than a live fleet, it says
 * so, with the actual window. Sensor status in this mode is measured against the end
 * of the capture, not the wall clock, so "online" means the sensor was still shipping
 * when the capture ended. Without this banner that reading could be mistaken for a
 * claim about right now.
 *
 * Renders nothing when the data is live, so it costs a live deployment nothing.
 */
import { useQuery } from "@tanstack/react-query";
import { Archive } from "lucide-react";
import { api } from "@/lib/api";

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso.replace(" ", "T"));
  return Number.isNaN(d.getTime())
    ? iso.slice(0, 10)
    : d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

export function DatasetBanner() {
  const { data } = useQuery({
    queryKey: ["analysisOverview"],
    queryFn: api.analysisOverview,
    staleTime: 600_000,
    retry: false,
  });

  const ds = data?.dataset;
  if (!ds?.archived) return null;

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-warn/20 bg-warn/[0.07] px-5 py-2 lg:px-7">
      <span className="flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-warn">
        <Archive className="h-3 w-3" /> Archived dataset
      </span>
      <span className="font-mono text-[11px] text-dim">
        {fmtDate(ds.window_start)} → {fmtDate(ds.window_end)} · {ds.days} days
      </span>
      <span className="font-mono text-[10.5px] text-muted">
        Sensor status is measured against the end of the capture, not the current time.
        Nothing here is live.
      </span>
    </div>
  );
}
