import { STATUS_COLOR } from "@/lib/theme";
import type { VpsStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

export function StatusDot({ status, size = 8 }: { status: VpsStatus; size?: number }) {
  const color = STATUS_COLOR[status];
  return (
    <span className="relative inline-flex shrink-0" style={{ width: size, height: size }}>
      {status === "online" && (
        <span
          className="absolute inset-0 rounded-full animate-pulse-ring"
          style={{ background: color }}
        />
      )}
      <span
        className={cn("relative rounded-full", status === "stale" && "animate-blink")}
        style={{ width: size, height: size, background: color, boxShadow: `0 0 8px ${color}` }}
      />
    </span>
  );
}
