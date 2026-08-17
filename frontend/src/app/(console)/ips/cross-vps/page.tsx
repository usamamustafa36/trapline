"use client";

import { useQuery } from "@tanstack/react-query";
import { Network, Skull, Radar } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import type { CrossVpsIp } from "@/lib/types";
import { fmtInt } from "@/lib/utils";
import { TopIpsTable } from "@/components/tables/TopIpsTable";
import { KpiTile } from "@/components/ui/KpiTile";
import { PageHeader } from "@/components/ui/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { ErrorState, Loader } from "@/components/ui/states";
import { cn } from "@/lib/utils";

type Sort = "events" | "coordination" | "sensors";
const SORTS: { key: Sort; label: string }[] = [
  { key: "coordination", label: "Coordination" },
  { key: "events", label: "Volume" },
  { key: "sensors", label: "Sensor Spread" },
];

export default function CrossVpsPage() {
  const [sort, setSort] = useState<Sort>("coordination");
  const q = useQuery({ queryKey: ["crossVps"], queryFn: () => api.crossVps(2), refetchInterval: 30_000 });

  const rows = useMemo(() => {
    const data = q.data ?? [];
    const sorted = [...data];
    sorted.sort((a: CrossVpsIp, b: CrossVpsIp) => {
      if (sort === "events") return b.total_events - a.total_events;
      if (sort === "sensors") return b.vps_count - a.vps_count || b.total_events - a.total_events;
      return b.coordination_score - a.coordination_score || b.total_events - a.total_events;
    });
    return sorted;
  }, [q.data, sort]);

  const coordinated = rows.filter((r) => r.coordination_score >= 70).length;
  const malicious = rows.filter((r) => (r.otx_pulse_count ?? 0) > 0).length;

  return (
    <div className="animate-fade-up">
      <PageHeader eyebrow="Intelligence · Correlation" title="Cross-VPS IP Linking" />

      <div className="mb-4 grid grid-cols-2 gap-4 md:grid-cols-3">
        <KpiTile
          label="Linked Indicators"
          value={fmtInt(rows.length)}
          sub="seen on 2+ sensors"
          accent="violet"
          icon={<Network className="h-4 w-4" />}
        />
        <KpiTile
          label="Coordinated"
          value={fmtInt(coordinated)}
          sub="score ≥ 70 · scripted recon"
          accent="hostile"
          icon={<Radar className="h-4 w-4" />}
        />
        <KpiTile
          label="OTX Malicious"
          value={fmtInt(malicious)}
          sub="known bad reputation"
          accent="signal"
          icon={<Skull className="h-4 w-4" />}
        />
      </div>

      <Panel
        title="Correlated Threat Actors"
        sub="IPs striking multiple honeypot sensors"
        icon={<Network className="h-4 w-4" />}
        right={
          <div className="inline-flex overflow-hidden rounded border border-line">
            {SORTS.map((s) => (
              <button
                  type="button"
                key={s.key}
                onClick={() => setSort(s.key)}
                className={cn(
                  "px-2.5 py-1 font-mono text-[10px] font-semibold uppercase tracking-wider transition-colors",
                  sort === s.key ? "bg-signal/15 text-signal" : "text-muted hover:text-dim",
                )}
              >
                {s.label}
              </button>
            ))}
          </div>
        }
      >
        {q.isLoading ? (
          <Loader />
        ) : q.isError ? (
          <ErrorState message={(q.error as Error)?.message} />
        ) : (
          <TopIpsTable rows={rows} />
        )}
      </Panel>
    </div>
  );
}
