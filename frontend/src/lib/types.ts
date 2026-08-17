// Mirrors backend Pydantic schemas (app/schemas.py).

export type VpsStatus = "online" | "stale" | "offline";

export interface Vps {
  id: string;
  alias: string;
  display_name: string;
  base_url: string | null;
  stack_type: string | null;
  region: string | null;
  lat: number | null;
  lon: number | null;
  is_active: boolean;
  last_seen_at: string | null;
  has_otx_key: boolean;
  status: VpsStatus;
  event_count: number;
}

export interface VpsHealth {
  alias: string;
  status: VpsStatus;
  last_seen_at: string | null;
  seconds_since: number | null;
}

export interface EventRow {
  id: number;
  event_uuid: string;
  vps_id: string;
  vps_alias: string | null;
  occurred_at: string;
  received_at: string;
  src_ip: string;
  dst_port: number | null;
  protocol: string | null;
  event_type: string | null;
  severity: number;
  username_tried: string | null;
  password_tried: string | null;
  payload_excerpt: string | null;
  country_code: string | null;
}

export interface PagedEvents {
  total: number;
  page: number;
  page_size: number;
  items: EventRow[];
  is_estimate: boolean;
}

export interface CrossVpsIp {
  ip: string;
  vps_count: number;
  vps_aliases: string[];
  total_events: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  country_code: string | null;
  otx_pulse_count: number | null;
  reputation_score: number | null;
  coordination_score: number;
}

export interface ThreatIntel {
  otx_pulse_count: number;
  reputation_score: number | null;
  tags: string[] | null;
  malware_families: string[] | null;
  last_checked_at: string | null;
}

export interface VpsBreakdown {
  vps_alias: string;
  display_name: string;
  event_count: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
  protocols: Record<string, number>;
}

export interface IpProfile {
  ip: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  total_events: number;
  vps_count: number;
  is_cross_vps: boolean;
  country_code: string | null;
  asn: string | null;
  vps_breakdown: VpsBreakdown[];
  threat_intel: ThreatIntel | null;
  coordination_score: number;
  recent_events: EventRow[];
}

export interface Kpi {
  events_24h: number;
  events_7d: number;
  events_30d: number;
  events_all: number;
  active_vps: number;
  total_vps: number;
  unique_ips: number;
  cross_vps_ips: number;
  known_malicious_ips: number;
}

export interface TimelinePoint {
  bucket: string;
  counts: Record<string, number>;
}

export interface NamedCount {
  name: string;
  count: number;
}

export interface GeoCount {
  country_code: string;
  count: number;
}

export interface StatsOverview {
  kpi: Kpi;
  timeline: TimelinePoint[];
  top_ips: CrossVpsIp[];
  event_types: NamedCount[];
  protocols: NamedCount[];
  geo: GeoCount[];
  vps_health: VpsHealth[];
  top_credentials: NamedCount[];
}

export type Window = "24h" | "7d" | "30d" | "all";
