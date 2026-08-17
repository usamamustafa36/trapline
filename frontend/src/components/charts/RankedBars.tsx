import type { NamedCount } from "@/lib/types";
import { fmtInt } from "@/lib/utils";

/** Ranked horizontal bars, single hue (magnitude). Direct value labels. */
export function RankedBars({
  data,
  hue = "#9FEF00",
  formatName = (n: string) => n,
  max: maxProp,
}: {
  data: NamedCount[];
  hue?: string;
  formatName?: (n: string) => string;
  max?: number;
}) {
  const max = maxProp ?? Math.max(1, ...data.map((d) => d.count));
  return (
    <div className="flex flex-col gap-2">
      {data.map((d) => {
        const pct = (d.count / max) * 100;
        return (
          <div key={d.name} className="group grid grid-cols-[130px_1fr_auto] items-center gap-3">
            <span className="truncate font-mono text-[11px] uppercase tracking-wide text-dim" title={d.name}>
              {formatName(d.name)}
            </span>
            <div className="relative h-[18px] overflow-hidden rounded-[3px] bg-white/[0.04]">
              <span
                className="absolute left-0 top-0 h-full rounded-[3px] transition-[width] duration-500"
                style={{
                  width: `${Math.max(pct, 2)}%`,
                  background: `linear-gradient(90deg, ${hue}33, ${hue})`,
                  boxShadow: `inset 0 0 0 1px ${hue}55`,
                }}
              />
            </div>
            <span className="tabular w-12 text-right font-mono text-[11px] font-semibold text-fg">
              {fmtInt(d.count)}
            </span>
          </div>
        );
      })}
    </div>
  );
}
