"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Radar,
  Network,
  FileBarChart,
  SlidersHorizontal,
  Radio,
  ShieldCheck,
} from "lucide-react";
import { api } from "@/lib/api";
import { STATUS_COLOR } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { StatusDot } from "@/components/ui/StatusDot";
import { ProjectLogo, VpsLogo } from "@/components/ui/VpsLogo";

const NAV = [
  { href: "/", label: "Overwatch", sub: "Aggregate", icon: Radar },
  { href: "/ips/cross-vps", label: "Cross-VPS", sub: "IP Linking", icon: Network },
  { href: "/reports", label: "Reports", sub: "Export", icon: FileBarChart },
  { href: "/settings/vps", label: "Sensors", sub: "Config", icon: SlidersHorizontal },
];

export function Sidebar() {
  const pathname = usePathname();
  const { data: vps } = useQuery({
    queryKey: ["vps"],
    queryFn: api.listVps,
    refetchInterval: 10_000,
  });

  return (
    <aside className="sticky top-0 hidden h-screen w-[248px] shrink-0 flex-col border-r border-white/[0.05] bg-base/60 backdrop-blur-xl lg:flex">
      {/* Brand */}
      <div className="relative flex items-center gap-3 overflow-hidden px-5 py-4">
        <span className="pointer-events-none absolute -left-10 -top-10 h-28 w-28 rounded-full bg-signal/12 blur-3xl" />
        <ProjectLogo />
        <div className="relative leading-tight">
          <div className="font-display text-[15px] font-bold tracking-wide text-fg">
            Trap<span className="text-signal text-glow-signal">line</span>
          </div>
          <div className="hud-label !text-[9px] text-muted">Central Honeypot Intelligence</div>
        </div>
      </div>

      {/* Primary nav */}
      <nav className="flex flex-col gap-1 px-3 py-2">
        <div className="hud-label px-2.5 pb-2">Operations</div>
        {NAV.map((item) => {
          const active = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-[13px] transition-all duration-200",
                active
                  ? "border border-signal/20 bg-signal/[0.08] text-fg"
                  : "border border-transparent text-dim hover:bg-white/[0.04] hover:text-fg",
              )}
            >
              <span
                className={cn(
                  "icon-chip h-8 w-8 transition-colors",
                  active
                    ? "border-signal/30 bg-signal/10 text-signal"
                    : "text-muted group-hover:text-dim",
                )}
              >
                <Icon className="h-[16px] w-[16px]" strokeWidth={1.9} />
              </span>
              <span className="flex-1 font-medium">{item.label}</span>
              <span className="hud-label !tracking-[0.1em] opacity-50">{item.sub}</span>
            </Link>
          );
        })}
      </nav>

      {/* Live sensor list */}
      <div className="mt-2 px-3 pt-1">
        <div className="hud-label flex items-center gap-1.5 px-2.5 pb-2">
          <Radio className="h-3 w-3" /> Sensor Grid
        </div>
        <div className="flex flex-col gap-1">
          {vps?.map((v) => {
            const active = pathname === `/vps/${v.alias}`;
            return (
              <Link
                key={v.id}
                href={`/vps/${v.alias}`}
                className={cn(
                  "flex items-center gap-2.5 rounded-xl border px-2.5 py-2 text-[13px] transition-all duration-200",
                  active
                    ? "border-white/[0.08] bg-white/[0.05] text-fg"
                    : "border-transparent text-dim hover:bg-white/[0.035]",
                )}
              >
                <VpsLogo alias={v.alias} size="sm" />
                <div className="min-w-0 flex-1">
                  <span className="font-mono text-[12px] font-semibold tracking-wide">{v.alias}</span>
                  <div className="truncate font-mono text-[10px] text-muted">{v.display_name}</div>
                </div>
                <StatusDot status={v.status} />
              </Link>
            );
          }) ?? (
            <div className="px-2.5 py-2 font-mono text-[11px] text-muted">acquiring…</div>
          )}
        </div>
      </div>

      {/* Footer status */}
      <div className="mt-auto p-3">
        <div className="flex items-center gap-2.5 rounded-xl border border-white/[0.06] bg-black/25 px-3 py-2.5">
          <span className="icon-chip h-8 w-8 border-ops/25 bg-ops/[0.08] text-ops">
            <ShieldCheck className="h-4 w-4" />
          </span>
          <div className="leading-tight">
            <div className="font-mono text-[10px] font-semibold uppercase tracking-wider text-ops">
              Link Secure
            </div>
            <div className="font-mono text-[9px] text-muted">TLS · Bearer · Rate-limited</div>
          </div>
          <span
            className="ml-auto h-2 w-2 rounded-full"
            style={{ background: STATUS_COLOR.online, boxShadow: `0 0 8px ${STATUS_COLOR.online}` }}
          />
        </div>
      </div>
    </aside>
  );
}
