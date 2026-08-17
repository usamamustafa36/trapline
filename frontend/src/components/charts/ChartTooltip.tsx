import { fmtInt } from "@/lib/utils";

interface Item {
  name?: string;
  value?: number | string;
  color?: string;
  dataKey?: string | number;
}

export function ChartTooltip({
  active,
  payload,
  label,
  labelFormatter,
  total,
}: {
  active?: boolean;
  payload?: Item[];
  label?: string | number;
  labelFormatter?: (l: string | number) => string;
  total?: boolean;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const sum = payload.reduce((a, p) => a + (typeof p.value === "number" ? p.value : 0), 0);
  return (
    <div className="min-w-[150px] rounded border border-line-bright bg-void/95 p-2.5 shadow-2xl backdrop-blur">
      {label != null && (
        <div className="mb-1.5 border-b border-line pb-1 font-mono text-[10px] uppercase tracking-wider text-muted">
          {labelFormatter ? labelFormatter(label) : label}
        </div>
      )}
      <div className="flex flex-col gap-1">
        {payload
          .slice()
          .reverse()
          .map((p, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px]">
              <span
                className="h-2.5 w-2.5 rounded-[2px]"
                style={{ background: p.color }}
              />
              <span className="font-mono uppercase tracking-wide text-dim">{p.name}</span>
              <span className="tabular ml-auto font-mono font-semibold text-fg">
                {fmtInt(typeof p.value === "number" ? p.value : Number(p.value))}
              </span>
            </div>
          ))}
        {total && payload.length > 1 && (
          <div className="mt-1 flex items-center gap-2 border-t border-line pt-1 text-[11px]">
            <span className="ml-auto font-mono uppercase tracking-wide text-muted">Σ Total</span>
            <span className="tabular font-mono font-bold text-signal">{fmtInt(sum)}</span>
          </div>
        )}
      </div>
    </div>
  );
}
