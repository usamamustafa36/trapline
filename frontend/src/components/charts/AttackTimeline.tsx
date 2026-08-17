"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { AXIS, GRID_STROKE, vpsColor } from "@/lib/theme";
import type { TimelinePoint, Window } from "@/lib/types";
import { fmtCompact } from "@/lib/utils";
import { ChartTooltip } from "./ChartTooltip";

export function AttackTimeline({
  data,
  window,
  height = 260,
}: {
  data: TimelinePoint[];
  window: Window;
  height?: number;
}) {
  // Fixed alias order → stable color assignment (never cycled).
  const aliases = Array.from(
    new Set(data.flatMap((d) => Object.keys(d.counts))),
  ).sort();

  const rows = data.map((d) => ({
    t: d.bucket,
    ...Object.fromEntries(aliases.map((a) => [a, d.counts[a] ?? 0])),
  }));

  const fmtX = (t: string | number) => {
    const d = new Date(t);
    if (window === "24h") {
      return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
    }
    if (window === "all") {
      return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "2-digit" });
    }
    return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
  };
  const fmtLabel = (t: string | number) =>
    new Date(t).toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    });

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1.5">
        {aliases.map((a, i) => (
          <span key={a} className="inline-flex items-center gap-1.5">
            <span
              className="h-2.5 w-2.5 rounded-[2px]"
              style={{ background: vpsColor(a, i) }}
            />
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-dim">
              {a}
            </span>
          </span>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={rows} margin={{ top: 4, right: 8, bottom: 0, left: -12 }}>
          <defs>
            {aliases.map((a, i) => (
              <linearGradient key={a} id={`grad-${a}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={vpsColor(a, i)} stopOpacity={0.5} />
                <stop offset="100%" stopColor={vpsColor(a, i)} stopOpacity={0.04} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke={GRID_STROKE} vertical={false} />
          <XAxis
            dataKey="t"
            tickFormatter={fmtX}
            stroke={AXIS.stroke}
            tick={AXIS.tick}
            tickLine={false}
            minTickGap={28}
          />
          <YAxis
            stroke={AXIS.stroke}
            tick={AXIS.tick}
            tickLine={false}
            axisLine={false}
            tickFormatter={(v) => fmtCompact(v)}
            width={44}
          />
          <Tooltip
            cursor={{ stroke: "#9FEF00", strokeWidth: 1, strokeDasharray: "3 3" }}
            content={<ChartTooltip labelFormatter={fmtLabel} total />}
          />
          {aliases.map((a, i) => (
            <Area
              key={a}
              type="monotone"
              dataKey={a}
              stackId="1"
              stroke={vpsColor(a, i)}
              strokeWidth={2}
              fill={`url(#grad-${a})`}
              isAnimationActive={false}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
