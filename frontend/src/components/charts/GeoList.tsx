import type { GeoCount } from "@/lib/types";
import { countryName, flag, fmtInt } from "@/lib/utils";
import { Empty } from "@/components/ui/states";

export function GeoList({ data, hue = "#3DE07A" }: { data: GeoCount[]; hue?: string }) {
  if (!data.length) return <Empty label="No geo telemetry" />;
  const max = Math.max(1, ...data.map((d) => d.count));
  return (
    <div className="flex flex-col gap-1.5">
      {data.slice(0, 10).map((g) => (
        <div key={g.country_code} className="grid grid-cols-[20px_1fr_auto] items-center gap-2.5">
          <span className="text-[14px] leading-none">{flag(g.country_code)}</span>
          <div className="min-w-0">
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="truncate font-mono text-[11px] text-dim">{countryName(g.country_code)}</span>
            </div>
            <div className="relative h-[6px] overflow-hidden rounded-full bg-white/[0.05]">
              <span
                className="absolute left-0 top-0 h-full rounded-full"
                style={{ width: `${(g.count / max) * 100}%`, background: hue, boxShadow: `0 0 6px ${hue}80` }}
              />
            </div>
          </div>
          <span className="tabular w-12 text-right font-mono text-[11px] font-semibold text-fg">
            {fmtInt(g.count)}
          </span>
        </div>
      ))}
    </div>
  );
}
