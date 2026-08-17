import type {
  CrossVpsIp,
  IpProfile,
  PagedEvents,
  StatsOverview,
  Vps,
  Window,
} from "./types";

const BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") ?? "http://localhost:8000/api/v1";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const url = new URL(`${BASE}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== "" && v !== null) url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url.toString(), { headers: { Accept: "application/json" } });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  base: BASE,
  health: () => get<{ status: string; version: string }>("/health"),
  overview: (window: Window) => get<StatsOverview>("/stats/overview", { window }),
  vpsStats: (alias: string, window: Window) => get<StatsOverview>(`/stats/${alias}`, { window }),
  listVps: () => get<Vps[]>("/vps"),
  events: (params: Record<string, string | number | undefined>) =>
    get<PagedEvents>("/events", params),
  crossVps: (min_vps = 2) => get<CrossVpsIp[]>("/ips/cross-vps", { min_vps }),
  ipProfile: (ip: string) => get<IpProfile>(`/ips/${encodeURIComponent(ip)}`),

  registerVps: async (
    payload: Record<string, unknown>,
    adminToken: string,
  ): Promise<{ id: string; alias: string; api_key: string; message: string }> => {
    const res = await fetch(`${BASE}/vps/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      let detail = res.statusText;
      try {
        detail = (await res.json()).detail ?? detail;
      } catch {
        /* ignore */
      }
      throw new ApiError(res.status, detail);
    }
    return res.json();
  },
};
