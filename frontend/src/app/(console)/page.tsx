"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/lib/api";
import type { Window } from "@/lib/types";
import { StatsDashboard } from "@/components/dashboard/StatsDashboard";
import { VpsHealthStrip } from "@/components/dashboard/VpsHealthStrip";
import { PageHeader } from "@/components/ui/PageHeader";
import { WindowToggle } from "@/components/ui/WindowToggle";
import { Panel } from "@/components/ui/Panel";
import { ErrorState, Loader } from "@/components/ui/states";

export default function OverviewPage() {
  const [window, setWindow] = useState<Window>("7d");

  const stats = useQuery({
    queryKey: ["overview", window],
    queryFn: () => api.overview(window),
    refetchInterval: 30_000,
  });
  const vps = useQuery({
    queryKey: ["vps"],
    queryFn: api.listVps,
    refetchInterval: 10_000,
  });

  return (
    <div className="animate-fade-up">
      <PageHeader eyebrow="Sector · Global Overwatch" title="Aggregate Threat Console">
        <WindowToggle value={window} onChange={setWindow} />
      </PageHeader>

      {vps.data && vps.data.length > 0 && (
        <div className="mb-4">
          <VpsHealthStrip sensors={vps.data} />
        </div>
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
        <StatsDashboard stats={stats.data} sensors={vps.data ?? []} window={window} scope={null} />
      ) : null}
    </div>
  );
}
