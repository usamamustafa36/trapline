"use client";

import { useQuery } from "@tanstack/react-query";
import {
  Fingerprint,
  MapPin,
  Radar,
  ShieldAlert,
  Network,
  Clock,
  Bug,
  Tag,
} from "lucide-react";
import { useParams } from "next/navigation";
import { api } from "@/lib/api";
import { vpsColor } from "@/lib/theme";
import { countryName, flag, fmtInt, fmtTime, relTime, scoreLabel } from "@/lib/utils";
import { EventTable } from "@/components/tables/EventTable";
import { Badge } from "@/components/ui/Badge";
import { CoordinationGauge, ReputationBadge } from "@/components/ui/indicators";
import { PageHeader } from "@/components/ui/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { ErrorState, Loader } from "@/components/ui/states";

export default function IpProfilePage() {
  const params = useParams<{ ip: string }>();
  const ip = decodeURIComponent(params.ip);
  const q = useQuery({ queryKey: ["ip", ip], queryFn: () => api.ipProfile(ip) });

  if (q.isLoading)
    return (
      <div className="animate-fade-up">
        <PageHeader eyebrow="Intelligence · IP Deep-Dive" title={ip} />
        <Panel>
          <Loader label="Compiling dossier…" />
        </Panel>
      </div>
    );

  if (q.isError || !q.data)
    return (
      <div className="animate-fade-up">
        <PageHeader eyebrow="Intelligence · IP Deep-Dive" title={ip} />
        <Panel>
          <ErrorState message={(q.error as Error)?.message ?? "Indicator not found in registry."} />
        </Panel>
      </div>
    );

  const p = q.data;
  const score = scoreLabel(p.coordination_score);
  const ti = p.threat_intel;

  return (
    <div className="animate-fade-up">
      <PageHeader eyebrow="Intelligence · IP Deep-Dive" title={p.ip}>
        {p.is_cross_vps && (
          <Badge tone="hostile" glow>
            <Network className="h-3 w-3" /> Cross-VPS ×{p.vps_count}
          </Badge>
        )}
      </PageHeader>

      {/* Dossier header */}
      <Panel className="mb-4" bracketed scanlines>
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1.4fr_1fr]">
          <div className="flex flex-col gap-4">
            <div className="flex items-center gap-4">
              <div className="grid h-14 w-14 shrink-0 place-items-center rounded border border-line bg-black/40 text-[26px]">
                {flag(p.country_code)}
              </div>
              <div>
                <div className="font-mono text-[20px] font-bold text-fg">{p.ip}</div>
                <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[11px] text-muted">
                  <span className="inline-flex items-center gap-1">
                    <MapPin className="h-3 w-3" /> {countryName(p.country_code)}
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <Fingerprint className="h-3 w-3" /> {p.asn ?? "ASN unknown"}
                  </span>
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Stat label="Total Events" value={fmtInt(p.total_events)} accent="text-signal" />
              <Stat label="Sensors Hit" value={`${p.vps_count}`} accent="text-recon" />
              <Stat label="First Seen" value={relTime(p.first_seen_at)} accent="text-dim" />
              <Stat label="Last Seen" value={relTime(p.last_seen_at)} accent="text-dim" />
            </div>
          </div>

          {/* Coordination assessment */}
          <div className="flex flex-col justify-center gap-3 rounded border border-line bg-black/30 p-4">
            <div className="hud-label flex items-center gap-1.5">
              <Radar className="h-3.5 w-3.5" /> Coordination Assessment
            </div>
            <div className="flex items-end gap-3">
              <div className="font-display text-[42px] font-bold leading-none" style={{ color: score.color }}>
                {p.coordination_score}
              </div>
              <div className="pb-1.5">
                <div
                  className="font-mono text-[13px] font-bold uppercase tracking-wider"
                  style={{ color: score.color }}
                >
                  {score.label}
                </div>
                <div className="font-mono text-[10px] text-muted">threat correlation index</div>
              </div>
            </div>
            <CoordinationGauge score={p.coordination_score} />
            <p className="font-mono text-[10px] leading-relaxed text-muted">
              {p.coordination_score >= 70
                ? "Struck multiple sensors within a tight window — likely scripted / coordinated recon."
                : p.coordination_score >= 40
                  ? "Correlated activity across sensors; monitor for campaign escalation."
                  : p.vps_count > 1
                    ? "Seen on multiple sensors but temporally dispersed — probable broad scanner."
                    : "Single-sensor activity; no cross-VPS correlation."}
            </p>
          </div>
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Left: per-sensor + events */}
        <div className="flex flex-col gap-4 xl:col-span-2">
          <Panel title="Per-Sensor Breakdown" sub="Where this indicator struck" icon={<Network className="h-4 w-4" />}>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {p.vps_breakdown.map((b) => (
                <div key={b.vps_alias} className="relative overflow-hidden rounded border border-line bg-black/20 p-3">
                  <span
                    className="absolute left-0 top-0 h-full w-[3px]"
                    style={{ background: vpsColor(b.vps_alias) }}
                  />
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[12px] font-bold text-fg">{b.vps_alias}</span>
                    <span className="tabular font-mono text-[13px] font-bold text-signal">
                      {fmtInt(b.event_count)}
                    </span>
                  </div>
                  <div className="mt-1 font-mono text-[10px] text-muted">{b.display_name}</div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {Object.entries(b.protocols).map(([proto, c]) => (
                      <span
                        key={proto}
                        className="rounded border border-line px-1.5 py-0.5 font-mono text-[9px] uppercase text-dim"
                      >
                        {proto} · {c}
                      </span>
                    ))}
                  </div>
                  <div className="mt-2 flex items-center gap-1 font-mono text-[9px] text-muted">
                    <Clock className="h-2.5 w-2.5" /> {relTime(b.first_seen_at)} → {relTime(b.last_seen_at)}
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel
            title="Merged Event Timeline"
            sub="All sensors · newest first"
            icon={<Clock className="h-4 w-4" />}
          >
            <EventTable rows={p.recent_events} />
          </Panel>
        </div>

        {/* Right: threat intel */}
        <div className="flex flex-col gap-4">
          <Panel title="Threat Intel" sub="AlienVault OTX" icon={<ShieldAlert className="h-4 w-4" />}>
            {ti ? (
              <div className="flex flex-col gap-4">
                <div className="flex items-center justify-between">
                  <span className="hud-label">Reputation</span>
                  <ReputationBadge pulses={ti.otx_pulse_count} score={ti.reputation_score} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <Stat label="OTX Pulses" value={fmtInt(ti.otx_pulse_count)} accent="text-hostile-soft" />
                  <Stat
                    label="Rep. Score"
                    value={ti.reputation_score != null ? ti.reputation_score.toFixed(2) : "—"}
                    accent="text-dim"
                  />
                </div>
                {ti.tags && ti.tags.length > 0 && (
                  <div>
                    <div className="hud-label mb-1.5 flex items-center gap-1">
                      <Tag className="h-3 w-3" /> Tags
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {ti.tags.map((t) => (
                        <Badge key={t} tone="signal">
                          {t}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {ti.malware_families && ti.malware_families.length > 0 && (
                  <div>
                    <div className="hud-label mb-1.5 flex items-center gap-1">
                      <Bug className="h-3 w-3" /> Malware Families
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {ti.malware_families.map((m) => (
                        <Badge key={m} tone="hostile">
                          {m}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                <div className="border-t border-line pt-2 font-mono text-[10px] text-muted">
                  Last checked {relTime(ti.last_checked_at)} · {fmtTime(ti.last_checked_at)}
                </div>
              </div>
            ) : (
              <div className="py-6 text-center">
                <ShieldAlert className="mx-auto mb-2 h-6 w-6 text-muted" />
                <p className="hud-label">No OTX record</p>
                <p className="mt-1 font-mono text-[10px] text-muted">
                  Indicator not yet enriched by the OTX worker.
                </p>
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string; accent: string }) {
  return (
    <div className="rounded border border-line bg-black/20 px-3 py-2">
      <div className="hud-label">{label}</div>
      <div className={`tabular mt-1 font-display text-[16px] font-bold ${accent}`}>{value}</div>
    </div>
  );
}
