"use client";

import { useQuery } from "@tanstack/react-query";
import { ExternalLink, Server } from "lucide-react";
import { useParams } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api";
import { STATUS_COLOR } from "@/lib/theme";
import type { Window } from "@/lib/types";
import { fmtInt, relTime } from "@/lib/utils";
import { StatsDashboard } from "@/components/dashboard/StatsDashboard";
import { PageHeader } from "@/components/ui/PageHeader";
import { WindowToggle } from "@/components/ui/WindowToggle";
import { Panel } from "@/components/ui/Panel";
import { StatusDot } from "@/components/ui/StatusDot";
import { Badge } from "@/components/ui/Badge";
import { VpsLogo } from "@/components/ui/VpsLogo";
import { ErrorState, Loader } from "@/components/ui/states";

export default function VpsPage() {
  const params = useParams<{ alias: string }>();
  const alias = params.alias;
  const [window, setWindow] = useState<Window>("7d");

  const vps = useQuery({ queryKey: ["vps"], queryFn: api.listVps, refetchInterval: 10_000 });
  const stats = useQuery({
    queryKey: ["vpsStats", alias, window],
    queryFn: () => api.vpsStats(alias, window),
    refetchInterval: 30_000,
  });

  const sensor = vps.data?.find((v) => v.alias === alias);

  return (
    <div className="animate-fade-up">
      <PageHeader eyebrow="Sensor Node · Individual" title={`Sensor ${alias}`}>
        <WindowToggle value={window} onChange={setWindow} />
      </PageHeader>

      {sensor && (
        <Panel className="mb-4" bracketed>
          <div className="flex flex-wrap items-center gap-4">
            <VpsLogo alias={sensor.alias} size="lg" />
            <div>
              <div className="font-display text-[16px] font-semibold text-fg">{sensor.display_name}</div>
              <div className="mt-0.5 flex items-center gap-2 font-mono text-[11px] text-muted">
                <Server className="h-3 w-3" />
                {sensor.region ?? "—"} · {sensor.stack_type ?? "—"}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <StatusDot status={sensor.status} />
              <span
                className="font-mono text-[11px] font-semibold uppercase tracking-wider"
                style={{ color: STATUS_COLOR[sensor.status] }}
              >
                {sensor.status}
              </span>
              <span className="font-mono text-[10px] text-muted">· {relTime(sensor.last_seen_at)}</span>
            </div>
            <div className="ml-auto flex items-center gap-3">
              {sensor.has_otx_key && <Badge tone="ops">OTX Linked</Badge>}
              <div className="text-right">
                <div className="hud-label">Total Events</div>
                <div className="tabular font-display text-[18px] font-bold text-signal">
                  {fmtInt(sensor.event_count)}
                </div>
              </div>
              {sensor.base_url && (
                <a
                  href={sensor.base_url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 rounded border border-line px-2.5 py-1.5 font-mono text-[11px] text-recon transition-colors hover:border-recon/50 hover:text-recon-soft"
                >
                  Local Console <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>
          </div>
        </Panel>
      )}

      {stats.isLoading ? (
        <Panel>
          <Loader />
        </Panel>
      ) : stats.isError ? (
        <Panel>
          <ErrorState message={(stats.error as Error)?.message} />
        </Panel>
      ) : stats.data ? (
        <StatsDashboard stats={stats.data} sensors={vps.data ?? []} window={window} scope={alias} />
      ) : null}
    </div>
  );
}
