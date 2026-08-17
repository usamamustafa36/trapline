"use client";

import type { Window } from "@/lib/types";
import { cn } from "@/lib/utils";

const OPTS: { key: Window; label: string }[] = [
  { key: "24h", label: "24H" },
  { key: "7d", label: "7D" },
  { key: "30d", label: "30D" },
  { key: "all", label: "ALL" },
];

export function WindowToggle({
  value,
  onChange,
}: {
  value: Window;
  onChange: (w: Window) => void;
}) {
  return (
    <div className="inline-flex items-center gap-0.5 rounded-full border border-white/[0.07] bg-black/25 p-1 backdrop-blur">
      {OPTS.map(({ key, label }) => (
        <button
                  type="button"
          key={key}
          onClick={() => onChange(key)}
          className={cn(
            "rounded-full px-3.5 py-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider transition-all duration-200",
            value === key
              ? "bg-signal text-void shadow-glow-signal"
              : "text-muted hover:bg-white/[0.05] hover:text-dim",
          )}
        >
          {label}
        </button>
      ))}
    </div>
  );
}
