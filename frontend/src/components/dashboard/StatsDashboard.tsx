"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Crosshair,
  Radio,
  Fingerprint,
  Network,
  Skull,
  Activity,
  Globe2,
  Waypoints,
  KeyRound,
  ListTree,
  Target,
} from "lucide-react";
import { api } from "@/lib/api";
import { HOSTILE, RECON, SIGNAL } from "@/lib/theme";
import type { StatsOverview, Vps, Window } from "@/lib/types";
import { fmtInt } from "@/lib/utils";
import { AttackTimeline } from "@/components/charts/AttackTimeline";
import { GeoList } from "@/components/charts/GeoList";
import { RankedBars } from "@/components/charts/RankedBars";
import { ThreatMap } from "@/components/charts/ThreatMap";
import { ThreatGlobe } from "@/components/charts/ThreatGlobe";
import { EventTable } from "@/components/tables/EventTable";
import { TopIpsTable } from "@/components/tables/TopIpsTable";
import { KpiTile } from "@/components/ui/KpiTile";
import { Panel } from "@/components/ui/Panel";

const fmtType = (n: string) => n.replace(/_/g, " ").toUpperCase();
const winLabel: Record<Window, string> = {
  "24h": "24 hours",
  "7d": "7 days",
  "30d": "30 days",
  all: "all time",
};

function eventsForWindow(k: StatsOverview["kpi"], w: Window) {
  if (w === "24h") return k.events_24h;
  if (w === "7d") return k.events_7d;
  if (w === "30d") return k.events_30d;
  return k.events_all;
}

export function StatsDashboard({
  stats,
  sensors,
  window,
  scope,
}: {
  stats: StatsOverview;
  sensors: Vps[];
  window: Window;
  scope: string | null;
}) {
  const { data: live } = useQuery({
    queryKey: ["events", scope, "live"],
    queryFn: () => api.events({ vps: scope ?? undefined, page_size: 14 }),
    refetchInterval: 12_000,
  });

  const k = stats.kpi;
  const coordinated = stats.top_ips.filter((i) => i.coordination_score >= 70).length;
  const isSensor = !!scope;
  const topProtocol = stats.protocols[0] ?? null;
  const topIp = stats.top_ips[0] ?? null;

  return (
    <div className="flex flex-col gap-4">
      {/* KPI strip — aggregate keeps sensors/cross-VPS; individual sensor swaps them */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        <KpiTile
          label={`Events · ${window === "all" ? "ALL" : window}`}
          value={fmtInt(eventsForWindow(k, window))}
          sub={window === "all" ? "total recorded" : `over ${winLabel[window]}`}
          accent="signal"
          icon={<Crosshair className="h-4 w-4" />}
        />
        {isSensor ? (
          <KpiTile
            label="Top Protocol"
            value={topProtocol ? topProtocol.name.toUpperCase() : "—"}
            sub={
              topProtocol
                ? `${fmtInt(topProtocol.count)} events · ${winLabel[window]}`
                : "no protocol data"
            }
            accent="ops"
            icon={<Waypoints className="h-4 w-4" />}
          />
        ) : (
          <KpiTile
            label="Active Sensors"
            value={`${k.active_vps}/${k.total_vps}`}
            sub="online / registered"
            accent="ops"
            icon={<Radio className="h-4 w-4" />}
          />
        )}
        <KpiTile
          label="Attacking IPs"
          value={fmtInt(k.unique_ips)}
          sub={window === "all" ? "unique sources tracked" : `unique in ${winLabel[window]}`}
          accent="recon"
          icon={<Fingerprint className="h-4 w-4" />}
        />
        {isSensor ? (
          <KpiTile
            label="Top Attacking IP"
            value={
              topIp ? (
                <span className="block truncate text-[22px] tracking-tight">{topIp.ip}</span>
              ) : (
                "—"
              )
            }
            sub={
              topIp
                ? `${fmtInt(topIp.total_events)} events · highest volume`
                : "no attacker data"
            }
            accent="violet"
            icon={<Target className="h-4 w-4" />}
          />
        ) : (
          <KpiTile
            label="Cross-VPS IPs"
            value={fmtInt(k.cross_vps_ips)}
            sub={`${coordinated} coordinated · ${window === "all" ? "all time" : winLabel[window]}`}
            accent="violet"
            icon={<Network className="h-4 w-4" />}
          />
        )}
        <KpiTile
          label="Known Malicious"
          value={fmtInt(k.known_malicious_ips)}
          sub={window === "all" ? "OTX-flagged indicators" : `OTX-flagged in ${winLabel[window]}`}
          accent="hostile"
          icon={<Skull className="h-4 w-4" />}
        />
      </div>

      {/* Timeline + vectors */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          title="Attack Timeline"
          sub={isSensor ? `Sensor ${scope} · ${winLabel[window]}` : `Stacked by sensor · ${winLabel[window]}`}
          icon={<Activity className="h-4 w-4" />}
          bracketed
          className="xl:col-span-2"
        >
          <AttackTimeline data={stats.timeline} window={window} />
        </Panel>
        <Panel title="Attack Vectors" sub="Event classification" icon={<ListTree className="h-4 w-4" />}>
          {stats.event_types.length ? (
            <RankedBars data={stats.event_types.slice(0, 8)} hue={SIGNAL} formatName={fmtType} />
          ) : (
            <div className="hud-label py-8 text-center">No vectors in range</div>
          )}
        </Panel>
      </div>

      {/* Threat map + origins/protocols */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          title="Global Threat Origin"
          sub={isSensor ? "Source geolocation · sensor uplinks" : "Live attack telemetry · rotating globe"}
          icon={<Globe2 className="h-4 w-4" />}
          bracketed
          scanlines
          className="xl:col-span-2"
        >
          {isSensor ? (
            <ThreatMap geo={stats.geo} sensors={sensors} />
          ) : (
            <ThreatGlobe geo={stats.geo} sensors={sensors} />
          )}
        </Panel>
        <div className="flex flex-col gap-4">
          <Panel title="Top Origins" sub="By attack volume" icon={<Globe2 className="h-4 w-4" />}>
            <GeoList data={stats.geo} />
          </Panel>
          <Panel title="Protocol Split" icon={<Waypoints className="h-4 w-4" />}>
            <RankedBars data={stats.protocols} hue={RECON} formatName={(n) => n.toUpperCase()} />
          </Panel>
        </div>
      </div>

      {/* Watchlist + credentials */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          title="Priority Watchlist"
          sub="Cross-VPS & high-volume threats"
          icon={<Skull className="h-4 w-4" />}
          className="xl:col-span-2"
        >
          <TopIpsTable rows={stats.top_ips} />
        </Panel>
        <Panel title="Credential Attacks" sub="Most-tried secrets" icon={<KeyRound className="h-4 w-4" />}>
          {stats.top_credentials.length ? (
            <RankedBars data={stats.top_credentials} hue={HOSTILE} />
          ) : (
            <div className="hud-label py-8 text-center">No credential data</div>
          )}
        </Panel>
      </div>

      {/* Live feed */}
      <Panel
        title="Live Event Feed"
        sub={scope ? `Sensor ${scope}` : "All sensors"}
        icon={<Activity className="h-4 w-4" />}
        right={
          <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-ops">
            <span className="h-1.5 w-1.5 animate-blink rounded-full bg-ops" /> streaming
          </span>
        }
      >
        <EventTable rows={live?.items ?? []} showVps={!scope} />
      </Panel>
    </div>
  );
}
