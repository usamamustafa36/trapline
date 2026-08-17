"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { GeoCount, Vps } from "@/lib/types";
import { COUNTRY_CENTROID, countryName, flag, fmtInt } from "@/lib/utils";

/**
 * ThreatGlobe — a dependency-free rotating globe (Canvas 2D, orthographic).
 * A dotted earth spins on a starfield while glowing attack arcs fly from real
 * source countries into the live sensor nodes. Auto-rotates, drag-to-spin,
 * hover an origin for its country + volume. Carbon-Neon themed.
 */

const DEG = Math.PI / 180;

// Rough continental silhouettes (lon,lat) — used only to classify which grid
// points are "land" for the dotted earth. Stylized, not survey-accurate.
const CONTINENTS: [number, number][][] = [
  // North America
  [[-168, 65], [-158, 71], [-130, 70], [-95, 80], [-82, 73], [-70, 62], [-56, 52], [-64, 45], [-81, 25], [-97, 26], [-107, 23], [-117, 32], [-125, 40], [-135, 58], [-168, 65]],
  // Greenland
  [[-45, 60], [-20, 70], [-20, 82], [-45, 83], [-58, 76], [-52, 64], [-45, 60]],
  // South America
  [[-80, 8], [-60, 5], [-50, 0], [-35, -6], [-40, -22], [-48, -30], [-58, -35], [-66, -45], [-72, -52], [-71, -40], [-76, -20], [-79, -5], [-80, 8]],
  // Europe
  [[-10, 36], [-9, 43], [-2, 48], [3, 51], [8, 58], [14, 66], [28, 71], [30, 62], [40, 60], [30, 50], [28, 44], [20, 40], [12, 38], [-6, 36], [-10, 36]],
  // Africa
  [[-16, 14], [-16, 25], [0, 34], [12, 34], [24, 32], [34, 31], [43, 12], [51, 12], [42, -2], [40, -16], [32, -28], [20, -35], [12, -18], [8, -2], [-8, 5], [-16, 14]],
  // Asia
  [[26, 45], [40, 45], [48, 40], [60, 42], [70, 30], [78, 8], [90, 22], [98, 8], [106, 10], [110, 22], [122, 30], [130, 43], [142, 50], [160, 62], [172, 66], [178, 70], [140, 73], [100, 76], [70, 74], [45, 68], [30, 58], [26, 45]],
  // India (peninsula emphasis)
  [[68, 24], [78, 8], [80, 8], [88, 22], [80, 30], [70, 30], [68, 24]],
  // SE Asia archipelago (Indonesia/Philippines approx)
  [[95, 6], [120, 6], [128, 8], [125, -2], [140, -4], [150, -8], [120, -10], [100, -4], [95, 6]],
  // Japan
  [[130, 31], [141, 36], [142, 43], [136, 37], [130, 31]],
  // British Isles
  [[-8, 51], [-2, 51], [-1, 58], [-6, 58], [-8, 51]],
  // Madagascar
  [[43, -13], [50, -15], [48, -25], [44, -22], [43, -13]],
  // Australia
  [[114, -22], [130, -12], [142, -11], [146, -18], [153, -28], [150, -38], [138, -36], [128, -32], [116, -34], [113, -26], [114, -22]],
  // New Zealand
  [[167, -44], [174, -41], [178, -38], [172, -46], [167, -44]],
];

function pointInPoly(lon: number, lat: number, poly: [number, number][]): boolean {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    const intersect =
      yi > lat !== yj > lat && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

// Precompute the dotted-earth grid ONCE — land classification is rotation-independent.
const LAND_DOTS: [number, number][] = (() => {
  const dots: [number, number][] = [];
  for (let lat = -78; lat <= 82; lat += 2.6) {
    const step = 2.6 / Math.max(Math.cos(lat * DEG), 0.22);
    for (let lon = -180; lon < 180; lon += step) {
      if (CONTINENTS.some((p) => pointInPoly(lon, lat, p))) dots.push([lon, lat]);
    }
  }
  return dots;
})();

// Threat intensity ramp: azure (low) → neon-lime (elevated) → red (high).
function threatColor(t: number): [number, number, number] {
  const stops: [number, [number, number, number]][] = [
    [0, [0x54, 0xae, 0xff]],
    [0.45, [0x9f, 0xef, 0x00]],
    [1, [0xff, 0x4d, 0x6d]],
  ];
  for (let i = 1; i < stops.length; i++) {
    if (t <= stops[i][0]) {
      const [t0, c0] = stops[i - 1];
      const [t1, c1] = stops[i];
      const k = (t - t0) / (t1 - t0 || 1);
      return [
        Math.round(c0[0] + (c1[0] - c0[0]) * k),
        Math.round(c0[1] + (c1[1] - c0[1]) * k),
        Math.round(c0[2] + (c1[2] - c0[2]) * k),
      ];
    }
  }
  return [0xff, 0x4d, 0x6d];
}

type Vec = { x: number; y: number; z: number };

function normalize(v: Vec): Vec {
  const m = Math.hypot(v.x, v.y, v.z) || 1;
  return { x: v.x / m, y: v.y / m, z: v.z / m };
}

// lon/lat → view-space unit vector, given yaw (spin) + tilt.
function toView(lon: number, lat: number, yaw: number, tilt: number): Vec {
  const la = lat * DEG;
  const lo = lon * DEG - yaw;
  const x0 = Math.cos(la) * Math.sin(lo);
  const y0 = Math.sin(la);
  const z0 = Math.cos(la) * Math.cos(lo);
  const ct = Math.cos(tilt);
  const st = Math.sin(tilt);
  return { x: x0, y: y0 * ct - z0 * st, z: y0 * st + z0 * ct };
}

// Spherical interpolation between two unit vectors.
function slerp(a: Vec, b: Vec, t: number): Vec {
  let dot = a.x * b.x + a.y * b.y + a.z * b.z;
  dot = Math.max(-1, Math.min(1, dot));
  const omega = Math.acos(dot);
  const so = Math.sin(omega);
  if (so < 1e-4) return a;
  const c1 = Math.sin((1 - t) * omega) / so;
  const c2 = Math.sin(t * omega) / so;
  return { x: a.x * c1 + b.x * c2, y: a.y * c1 + b.y * c2, z: a.z * c1 + b.z * c2 };
}

interface OriginPt {
  cc: string;
  lon: number;
  lat: number;
  count: number;
  t: number;
  color: [number, number, number];
}
interface NodePt {
  alias: string;
  lon: number;
  lat: number;
}
interface Arc {
  origin: OriginPt;
  node: NodePt;
  phase: number;
}
interface Link {
  a: OriginPt;
  b: OriginPt;
  color: [number, number, number];
  phase: number;
}
interface ScreenOrigin {
  sx: number;
  sy: number;
  visible: boolean;
  o: OriginPt;
}

export function ThreatGlobe({ geo, sensors }: { geo: GeoCount[]; sensors: Vps[] }) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [hover, setHover] = useState<{ x: number; y: number; o: OriginPt } | null>(null);

  const origins = useMemo<OriginPt[]>(() => {
    const withCentroid = geo.filter((g) => COUNTRY_CENTROID[g.country_code]);
    const max = Math.max(1, ...withCentroid.map((g) => g.count));
    return withCentroid
      .map((g) => {
        const [lon, lat] = COUNTRY_CENTROID[g.country_code];
        const t = g.count / max;
        return { cc: g.country_code, lon, lat, count: g.count, t, color: threatColor(t) };
      })
      .sort((a, b) => a.count - b.count);
  }, [geo]);

  const nodes = useMemo<NodePt[]>(
    () =>
      sensors
        .filter((s) => s.lat != null && s.lon != null)
        .map((s) => ({ alias: s.alias, lon: Number(s.lon), lat: Number(s.lat) })),
    [sensors],
  );

  const arcs = useMemo<Arc[]>(() => {
    if (nodes.length === 0) return [];
    const top = origins.slice(-12);
    return top.map((o, i) => {
      let best = nodes[0];
      let bestD = Infinity;
      for (const n of nodes) {
        const d = Math.hypot(n.lon - o.lon, n.lat - o.lat);
        if (d < bestD) {
          bestD = d;
          best = n;
        }
      }
      return { origin: o, node: best, phase: (i / Math.max(1, top.length)) * Math.PI * 2 };
    });
  }, [origins, nodes]);

  // Interconnect the top origins with each other (all-pairs network mesh).
  const links = useMemo<Link[]>(() => {
    const top = origins.slice(-9);
    const out: Link[] = [];
    let k = 0;
    for (let i = 0; i < top.length; i++) {
      for (let j = i + 1; j < top.length; j++) {
        const ca = top[i].color;
        const cb = top[j].color;
        out.push({
          a: top[i],
          b: top[j],
          color: [
            Math.round((ca[0] + cb[0]) / 2),
            Math.round((ca[1] + cb[1]) / 2),
            Math.round((ca[2] + cb[2]) / 2),
          ],
          phase: k++ * 0.7,
        });
      }
    }
    return out;
  }, [origins]);

  // Keep latest render data in a ref so the animation loop never restarts on refetch.
  const dataRef = useRef({ origins, nodes, arcs, links });
  useEffect(() => {
    dataRef.current = { origins, nodes, arcs, links };
  }, [origins, nodes, arcs, links]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!canvas || !wrap) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let cssW = 0;
    let cssH = 0;
    let dpr = 1;
    const stars: { x: number; y: number; r: number; a: number; tw: number }[] = [];

    function seedStars() {
      stars.length = 0;
      const n = Math.round((cssW * cssH) / 5200);
      for (let i = 0; i < n; i++) {
        stars.push({
          x: Math.random() * cssW,
          y: Math.random() * cssH,
          r: Math.random() * 1.1 + 0.2,
          a: Math.random() * 0.5 + 0.15,
          tw: Math.random() * Math.PI * 2,
        });
      }
    }

    function resize() {
      const rect = wrap!.getBoundingClientRect();
      cssW = Math.max(1, rect.width);
      cssH = Math.max(1, rect.height);
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas!.width = Math.round(cssW * dpr);
      canvas!.height = Math.round(cssH * dpr);
      canvas!.style.width = `${cssW}px`;
      canvas!.style.height = `${cssH}px`;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      seedStars();
    }

    const ro = new ResizeObserver(resize);
    ro.observe(wrap);
    resize();

    // rotation state (persists across data refetches — effect runs once)
    let yaw = -0.5;
    let tilt = -0.32;
    let dragging = false;
    let lastX = 0;
    let lastY = 0;
    let resumeAt = 0;
    const screenOrigins: ScreenOrigin[] = [];

    function onDown(e: PointerEvent) {
      dragging = true;
      lastX = e.clientX;
      lastY = e.clientY;
      canvas!.setPointerCapture?.(e.pointerId);
      canvas!.style.cursor = "grabbing";
    }
    function onMove(e: PointerEvent) {
      const rect = canvas!.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      if (dragging) {
        yaw += (e.clientX - lastX) * 0.006;
        tilt = Math.max(-1.15, Math.min(1.15, tilt + (e.clientY - lastY) * 0.006));
        lastX = e.clientX;
        lastY = e.clientY;
        resumeAt = performance.now() + 2400;
        return;
      }
      // hover hit-test against last-drawn origins
      let found: ScreenOrigin | null = null;
      let bestD = 16;
      for (const s of screenOrigins) {
        if (!s.visible) continue;
        const d = Math.hypot(s.sx - mx, s.sy - my);
        if (d < bestD) {
          bestD = d;
          found = s;
        }
      }
      if (found) {
        setHover({ x: found.sx, y: found.sy, o: found.o });
        canvas!.style.cursor = "pointer";
      } else {
        setHover(null);
        canvas!.style.cursor = "grab";
      }
    }
    function onUp(e: PointerEvent) {
      dragging = false;
      resumeAt = performance.now() + 2000;
      canvas!.releasePointerCapture?.(e.pointerId);
      canvas!.style.cursor = "grab";
    }
    function onLeave() {
      if (!dragging) setHover(null);
    }
    canvas.style.cursor = "grab";
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointerleave", onLeave);

    let raf = 0;
    function frame(now: number) {
      const { origins: OR, nodes: ND, arcs: AR, links: ML } = dataRef.current;
      if (!dragging && now >= resumeAt && !reduce) {
        yaw += 0.0016;
      }

      const cx = cssW / 2;
      const cy = cssH / 2;
      const R = Math.min(cssW, cssH) * 0.46;

      ctx!.clearRect(0, 0, cssW, cssH);

      // starfield
      for (const s of stars) {
        const a = reduce ? s.a : s.a * (0.6 + 0.4 * Math.sin(now * 0.001 + s.tw));
        ctx!.beginPath();
        ctx!.arc(s.x, s.y, s.r, 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(200,220,255,${a.toFixed(3)})`;
        ctx!.fill();
      }

      // atmosphere halo (outer glow → adds volume / 3D lift)
      const halo = ctx!.createRadialGradient(cx, cy, R * 0.78, cx, cy, R * 1.32);
      halo.addColorStop(0, "rgba(84,174,255,0)");
      halo.addColorStop(0.66, "rgba(84,174,255,0.06)");
      halo.addColorStop(0.86, "rgba(159,239,0,0.13)");
      halo.addColorStop(0.95, "rgba(84,174,255,0.05)");
      halo.addColorStop(1, "rgba(84,174,255,0)");
      ctx!.fillStyle = halo;
      ctx!.beginPath();
      ctx!.arc(cx, cy, R * 1.32, 0, Math.PI * 2);
      ctx!.fill();

      // sphere body (shaded, light from upper-left)
      const body = ctx!.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.1, cx, cy, R);
      body.addColorStop(0, "rgba(21,34,52,0.95)");
      body.addColorStop(0.6, "rgba(12,20,33,0.96)");
      body.addColorStop(1, "rgba(6,10,18,0.98)");
      ctx!.beginPath();
      ctx!.arc(cx, cy, R, 0, Math.PI * 2);
      ctx!.fillStyle = body;
      ctx!.fill();

      // clip to sphere for the surface layer
      ctx!.save();
      ctx!.beginPath();
      ctx!.arc(cx, cy, R, 0, Math.PI * 2);
      ctx!.clip();

      // graticule (faint meridians/parallels on the front hemisphere)
      ctx!.strokeStyle = "rgba(120,150,190,0.07)";
      ctx!.lineWidth = 0.6;
      for (let lon = -180; lon < 180; lon += 30) {
        ctx!.beginPath();
        let started = false;
        for (let lat = -90; lat <= 90; lat += 6) {
          const v = toView(lon, lat, yaw, tilt);
          if (v.z <= 0) {
            started = false;
            continue;
          }
          const px = cx + R * v.x;
          const py = cy - R * v.y;
          if (!started) {
            ctx!.moveTo(px, py);
            started = true;
          } else ctx!.lineTo(px, py);
        }
        ctx!.stroke();
      }
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx!.beginPath();
        let started = false;
        for (let lon = -180; lon <= 180; lon += 6) {
          const v = toView(lon, lat, yaw, tilt);
          if (v.z <= 0) {
            started = false;
            continue;
          }
          const px = cx + R * v.x;
          const py = cy - R * v.y;
          if (!started) {
            ctx!.moveTo(px, py);
            started = true;
          } else ctx!.lineTo(px, py);
        }
        ctx!.stroke();
      }

      // dotted earth
      for (const [lon, lat] of LAND_DOTS) {
        const v = toView(lon, lat, yaw, tilt);
        if (v.z <= 0.02) continue;
        const px = cx + R * v.x;
        const py = cy - R * v.y;
        const depth = 0.35 + 0.65 * v.z;
        ctx!.beginPath();
        ctx!.arc(px, py, 0.9 * depth + 0.3, 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(94,150,150,${(0.16 + 0.34 * v.z).toFixed(3)})`;
        ctx!.fill();
      }
      ctx!.restore();

      // terminator shading (day/night sphere depth)
      const term = ctx!.createRadialGradient(cx - R * 0.3, cy - R * 0.35, R * 0.2, cx + R * 0.2, cy + R * 0.25, R * 1.05);
      term.addColorStop(0, "rgba(0,0,0,0)");
      term.addColorStop(1, "rgba(2,5,12,0.5)");
      ctx!.save();
      ctx!.beginPath();
      ctx!.arc(cx, cy, R, 0, Math.PI * 2);
      ctx!.clip();
      ctx!.fillStyle = term;
      ctx!.fillRect(cx - R, cy - R, R * 2, R * 2);
      ctx!.restore();

      // specular gloss — a glassy highlight upper-left for a 3D sphere read
      const spec = ctx!.createRadialGradient(
        cx - R * 0.42, cy - R * 0.46, R * 0.02,
        cx - R * 0.42, cy - R * 0.46, R * 0.95,
      );
      spec.addColorStop(0, "rgba(150,200,255,0.16)");
      spec.addColorStop(0.5, "rgba(150,200,255,0.04)");
      spec.addColorStop(1, "rgba(150,200,255,0)");
      ctx!.save();
      ctx!.beginPath();
      ctx!.arc(cx, cy, R, 0, Math.PI * 2);
      ctx!.clip();
      ctx!.fillStyle = spec;
      ctx!.fillRect(cx - R, cy - R, R * 2, R * 2);
      ctx!.restore();

      // rim light (azure edge + faint lime bloom)
      ctx!.beginPath();
      ctx!.arc(cx, cy, R, 0, Math.PI * 2);
      ctx!.strokeStyle = "rgba(84,174,255,0.32)";
      ctx!.lineWidth = 1.1;
      ctx!.stroke();

      // origin ↔ origin network mesh — interconnect all top origins with
      // great-circle links wrapping the sphere (occlusion-aware for depth).
      const HM = 0.16;
      for (const link of ML) {
        const a = toView(link.a.lon, link.a.lat, yaw, tilt);
        const b = toView(link.b.lon, link.b.lat, yaw, tilt);
        const mid = normalize(slerp(a, b, 0.5));
        const midLift = 1 + HM;
        const occ = mid.z < 0 && Math.hypot(mid.x * midLift, mid.y * midLift) < 1;
        const shimmer = reduce ? 1 : 0.6 + 0.4 * Math.sin(now * 0.0011 + link.phase);
        const [lr, lg, lb] = link.color;
        const SEG = 30;
        ctx!.beginPath();
        for (let i = 0; i <= SEG; i++) {
          const t = i / SEG;
          const v = normalize(slerp(a, b, t));
          const lift = 1 + HM * Math.sin(Math.PI * t);
          const px = cx + R * v.x * lift;
          const py = cy - R * v.y * lift;
          if (i === 0) ctx!.moveTo(px, py);
          else ctx!.lineTo(px, py);
        }
        ctx!.lineWidth = 0.8;
        ctx!.strokeStyle = `rgba(${lr},${lg},${lb},${((occ ? 0.05 : 0.22) * shimmer).toFixed(3)})`;
        ctx!.stroke();
      }

      // attack arcs
      const H = 0.42;
      for (const arc of AR) {
        const a = toView(arc.origin.lon, arc.origin.lat, yaw, tilt);
        const b = toView(arc.node.lon, arc.node.lat, yaw, tilt);
        const [r, g, bl] = arc.origin.color;
        const SEG = 44;
        ctx!.lineWidth = 1.4;
        let prev: { x: number; y: number; occ: boolean } | null = null;
        for (let i = 0; i <= SEG; i++) {
          const t = i / SEG;
          const v = normalize(slerp(a, b, t));
          const lift = 1 + H * Math.sin(Math.PI * t);
          const px = cx + R * v.x * lift;
          const py = cy - R * v.y * lift;
          const occ = v.z < 0 && Math.hypot(v.x * lift, v.y * lift) < 1;
          if (prev) {
            ctx!.beginPath();
            ctx!.moveTo(prev.x, prev.y);
            ctx!.lineTo(px, py);
            const edgeFade = Math.sin(Math.PI * t);
            const alpha = (occ ? 0.08 : 0.5) * (0.35 + 0.65 * edgeFade);
            ctx!.strokeStyle = `rgba(${r},${g},${bl},${alpha.toFixed(3)})`;
            ctx!.stroke();
          }
          prev = { x: px, y: py, occ };
        }
        // traveling pulse
        if (!reduce) {
          const tp = (now * 0.00042 + arc.phase / (Math.PI * 2)) % 1;
          const v = normalize(slerp(a, b, tp));
          const lift = 1 + H * Math.sin(Math.PI * tp);
          const px = cx + R * v.x * lift;
          const py = cy - R * v.y * lift;
          const occ = v.z < 0 && Math.hypot(v.x * lift, v.y * lift) < 1;
          if (!occ) {
            ctx!.save();
            ctx!.shadowColor = `rgba(${r},${g},${bl},0.9)`;
            ctx!.shadowBlur = 10;
            ctx!.beginPath();
            ctx!.arc(px, py, 2.4, 0, Math.PI * 2);
            ctx!.fillStyle = `rgba(${r},${g},${bl},1)`;
            ctx!.fill();
            ctx!.restore();
          }
        }
      }

      // origin markers
      screenOrigins.length = 0;
      const maxCount = Math.max(1, ...OR.map((o) => o.count));
      for (const o of OR) {
        const v = toView(o.lon, o.lat, yaw, tilt);
        const px = cx + R * v.x;
        const py = cy - R * v.y;
        const visible = v.z > 0;
        screenOrigins.push({ sx: px, sy: py, visible, o });
        if (!visible) continue;
        const [r, g, bl] = o.color;
        const rad = 1.8 + Math.sqrt(o.count / maxCount) * 6;
        ctx!.beginPath();
        ctx!.arc(px, py, rad * 2.4, 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(${r},${g},${bl},0.14)`;
        ctx!.fill();
        ctx!.save();
        ctx!.shadowColor = `rgba(${r},${g},${bl},0.85)`;
        ctx!.shadowBlur = 8;
        ctx!.beginPath();
        ctx!.arc(px, py, Math.min(rad, 3.4), 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(${r},${g},${bl},0.95)`;
        ctx!.fill();
        ctx!.restore();
      }

      // sensor nodes (emerald diamonds + sonar ping)
      for (const n of ND) {
        const v = toView(n.lon, n.lat, yaw, tilt);
        if (v.z <= 0) continue;
        const px = cx + R * v.x;
        const py = cy - R * v.y;
        if (!reduce) {
          const ping = (now * 0.0009 + (n.alias.charCodeAt(0) % 7) * 0.4) % 1;
          ctx!.beginPath();
          ctx!.arc(px, py, 4 + ping * 12, 0, Math.PI * 2);
          ctx!.strokeStyle = `rgba(61,224,122,${(0.4 * (1 - ping)).toFixed(3)})`;
          ctx!.lineWidth = 1.2;
          ctx!.stroke();
        }
        ctx!.save();
        ctx!.translate(px, py);
        ctx!.rotate(Math.PI / 4);
        ctx!.shadowColor = "rgba(61,224,122,0.9)";
        ctx!.shadowBlur = 9;
        ctx!.fillStyle = "#3DE07A";
        ctx!.fillRect(-4, -4, 8, 8);
        ctx!.restore();
        ctx!.font = "700 9px ui-monospace, SFMono-Regular, Menlo, monospace";
        ctx!.fillStyle = "rgba(124,240,166,0.95)";
        ctx!.textAlign = "center";
        ctx!.fillText(n.alias, px, py - 9);
      }

      raf = requestAnimationFrame(frame);
    }
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      canvas.removeEventListener("pointerdown", onDown);
      canvas.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      canvas.removeEventListener("pointerleave", onLeave);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <div ref={wrapRef} className="relative w-full" style={{ aspectRatio: "16 / 10" }}>
        <canvas ref={canvasRef} className="absolute inset-0 h-full w-full touch-none" />
        {hover && (
          <div
            className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded-lg border border-white/10 bg-void/90 px-2.5 py-1.5 shadow-xl backdrop-blur"
            style={{ left: hover.x, top: hover.y - 10 }}
          >
            <div className="flex items-center gap-1.5 font-mono text-[11px] font-semibold text-fg">
              <span>{flag(hover.o.cc)}</span>
              {countryName(hover.o.cc)}
            </div>
            <div className="mt-0.5 font-mono text-[10px]" style={{ color: `rgb(${hover.o.color.join(",")})` }}>
              {fmtInt(hover.o.count)} events
            </div>
          </div>
        )}
        <div className="pointer-events-none absolute left-3 top-3 flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-[0.16em] text-muted">
          <span className="h-1.5 w-1.5 animate-blink rounded-full bg-ops" /> Live · drag to rotate
        </div>
      </div>

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
