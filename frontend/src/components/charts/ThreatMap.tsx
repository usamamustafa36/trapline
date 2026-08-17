"use client";

import { useMemo } from "react";
import type { GeoCount, Vps } from "@/lib/types";
import { COUNTRY_CENTROID, countryName, fmtInt } from "@/lib/utils";

const W = 720;
const H = 360;

const project = (lon: number, lat: number): [number, number] => [
  ((lon + 180) / 360) * W,
  ((90 - lat) / 180) * H,
];

// Rough low-detail continents (lon,lat) — grounding silhouettes only.
const CONTINENTS: [number, number][][] = [
  [[-168,65],[-140,70],[-95,80],[-70,62],[-55,50],[-72,43],[-81,25],[-105,22],[-125,40],[-135,58],[-168,65]],
  [[-80,8],[-60,5],[-42,-5],[-40,-20],[-58,-35],[-72,-52],[-70,-35],[-78,-5],[-80,8]],
  [[-10,36],[-2,48],[3,51],[5,60],[28,70],[30,58],[35,50],[28,44],[12,38],[-6,36]],
  [[-16,14],[-16,25],[10,33],[32,31],[43,12],[51,12],[40,-10],[25,-34],[12,-18],[-8,5],[-16,14]],
  [[35,50],[45,40],[60,25],[75,8],[90,22],[100,8],[120,35],[130,43],[140,50],[160,62],[170,68],[140,73],[80,76],[45,68],[35,50]],
  [[114,-22],[130,-12],[142,-11],[153,-28],[150,-38],[130,-32],[114,-30],[114,-22]],
];

function threatColor(t: number): string {
  // intensity ramp azure → neon-lime → red (higher volume = hotter)
  const stops: [number, [number, number, number]][] = [
    [0, [0x54, 0xae, 0xff]],
    [0.4, [0x9f, 0xef, 0x00]],
    [1, [0xff, 0x4d, 0x6d]],
  ];
  for (let i = 1; i < stops.length; i++) {
    if (t <= stops[i][0]) {
      const [t0, c0] = stops[i - 1];
      const [t1, c1] = stops[i];
      const k = (t - t0) / (t1 - t0 || 1);
      const c = c0.map((v, j) => Math.round(v + (c1[j] - v) * k));
      return `rgb(${c[0]},${c[1]},${c[2]})`;
    }
  }
  return "rgb(255,77,109)";
}

export function ThreatMap({ geo, sensors }: { geo: GeoCount[]; sensors: Vps[] }) {
  const points = useMemo(() => {
    const max = Math.max(1, ...geo.map((g) => g.count));
    return geo
      .filter((g) => COUNTRY_CENTROID[g.country_code])
      .map((g) => {
        const [lon, lat] = COUNTRY_CENTROID[g.country_code];
        const [x, y] = project(lon, lat);
        const t = g.count / max;
        return { ...g, x, y, t, r: 3 + Math.sqrt(t) * 13, color: threatColor(t) };
      })
      .sort((a, b) => a.count - b.count);
  }, [geo]);

  const nodes = useMemo(
    () =>
      sensors
        .filter((s) => s.lat != null && s.lon != null)
        .map((s) => {
          const [x, y] = project(Number(s.lon), Number(s.lat));
          return { ...s, x, y };
        }),
    [sensors],
  );

  const top = points.slice(-8);
  const meridians = [-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150];
  const parallels = [-60, -30, 0, 30, 60];

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" style={{ aspectRatio: "2 / 1" }}>
        <defs>
          <radialGradient id="map-vignette" cx="50%" cy="45%" r="75%">
            <stop offset="70%" stopColor="transparent" />
            <stop offset="100%" stopColor="rgba(6,10,18,0.55)" />
          </radialGradient>
          <filter id="glow-map" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* continents */}
        {CONTINENTS.map((poly, i) => (
          <polygon
            key={i}
            points={poly.map(([lon, lat]) => project(lon, lat).join(",")).join(" ")}
            fill="rgba(84,174,255,0.05)"
            stroke="rgba(84,174,255,0.18)"
            strokeWidth={0.6}
          />
        ))}

        {/* graticule */}
        {meridians.map((lon) => {
          const [x] = project(lon, 0);
          return <line key={`m${lon}`} x1={x} y1={0} x2={x} y2={H} stroke="rgba(120,140,170,0.08)" strokeWidth={0.5} />;
        })}
        {parallels.map((lat) => {
          const [, y] = project(0, lat);
          return <line key={`p${lat}`} x1={0} y1={y} x2={W} y2={y} stroke="rgba(120,140,170,0.08)" strokeWidth={0.5} />;
        })}
        <line x1={0} y1={H / 2} x2={W} y2={H / 2} stroke="rgba(159,239,0,0.16)" strokeWidth={0.7} strokeDasharray="2 4" />

        {/* attack arcs: each top origin → nearest sensor node */}
        {top.map((p) => {
          if (nodes.length === 0) return null;
          const n = nodes.reduce((best, s) =>
            Math.hypot(s.x - p.x, s.y - p.y) < Math.hypot(best.x - p.x, best.y - p.y) ? s : best,
          );
          const mx = (p.x + n.x) / 2;
          const my = (p.y + n.y) / 2 - Math.hypot(n.x - p.x, n.y - p.y) * 0.28;
          return (
            <path
              key={`arc-${p.country_code}`}
              d={`M${p.x},${p.y} Q${mx},${my} ${n.x},${n.y}`}
              fill="none"
              stroke={p.color}
              strokeWidth={0.8}
              strokeOpacity={0.4}
              strokeDasharray="3 3"
            />
          );
        })}

        {/* origin markers */}
        {points.map((p) => (
          <g key={p.country_code} filter="url(#glow-map)">
            <circle cx={p.x} cy={p.y} r={p.r} fill={p.color} fillOpacity={0.16} />
            <circle cx={p.x} cy={p.y} r={Math.min(p.r, 3.5)} fill={p.color} fillOpacity={0.95}>
              <title>
                {countryName(p.country_code)} ({p.country_code}) — {fmtInt(p.count)} events
              </title>
            </circle>
          </g>
        ))}

        {/* sensor nodes (diamonds) */}
        {nodes.map((n) => (
          <g key={n.alias}>
            <circle cx={n.x} cy={n.y} r={9} fill="none" stroke="#3DE07A" strokeOpacity={0.35}>
              <animate attributeName="r" values="6;13;6" dur="3s" repeatCount="indefinite" />
              <animate attributeName="stroke-opacity" values="0.5;0;0.5" dur="3s" repeatCount="indefinite" />
            </circle>
            <rect
              x={n.x - 4}
              y={n.y - 4}
              width={8}
              height={8}
              transform={`rotate(45 ${n.x} ${n.y})`}
              fill="#3DE07A"
              stroke="#0B111C"
              strokeWidth={1}
            />
            <text x={n.x} y={n.y - 10} textAnchor="middle" className="fill-ops font-mono" fontSize={9} fontWeight={700}>
              {n.alias}
            </text>
          </g>
        ))}

        {/* labels for top origins */}
        {top.map((p) => (
          <text
            key={`lbl-${p.country_code}`}
            x={p.x + p.r + 2}
            y={p.y + 3}
            className="fill-dim font-mono"
            fontSize={8.5}
          >
            {p.country_code}
          </text>
        ))}

        <rect x={0} y={0} width={W} height={H} fill="url(#map-vignette)" pointerEvents="none" />
      </svg>

      {/* legend */}
      <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1.5">
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rotate-45 bg-ops" />
          <span className="hud-label">Sensor Node</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-recon" />
          <span className="hud-label">Low Volume</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-signal" />
          <span className="hud-label">Elevated</span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-hostile" />
          <span className="hud-label">High Volume</span>
        </span>
      </div>
    </div>
  );
}
