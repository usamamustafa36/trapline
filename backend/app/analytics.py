"""
Analytics over collected honeypot telemetry.

Every function here answers a question the raw event feed cannot, and each one is
written so its output carries the evidence behind it: counts, example rows, and the
addresses involved. Nothing returns a bare score.

The analyses, and why each exists:

- `coordination`      cross-sensor attribution. An address seen by several sensors is
                      classified by the *shape* of its inter-sensor lag: a tight
                      ordered walk is one scanner sweeping a range, near-simultaneous
                      arrivals are a distributed botnet, and months apart is
                      background radiation. Distinguishing these is the open question
                      in the deception literature, not the flag itself.
- `client_fingerprints` SSH version strings are tool fingerprints. `libssh` and Go
                      clients are automation; PuTTY and OpenSSH-for-Windows are
                      interactive clients, which is the strongest available signal
                      for a human at the keyboard.
- `credential_ladders` the ordered password sequence a source tries is a tool
                      signature. Two sources emitting the same ladder in the same
                      order are running the same software.
- `guessing_style`    separates password guessing from spraying from stuffing by
                      account-to-password fan-out, which is a real MITRE
                      sub-technique distinction rather than a decorative badge.
- `command_phases`    maps observed shell commands onto attack-lifecycle phases and
                      ATT&CK techniques, with the matching commands kept as evidence.
- `rhythm`            hour-of-day activity. A flat profile means continuous
                      automation. A diurnal shape indicates *a* schedule, which may be
                      the operator's working hours or the victim population powering
                      down, and is weaker evidence of human presence than the client
                      fingerprints are.

Run standalone for a text report:

    python -m app.analytics
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Event, VpsSource

# ── Tunables, stated rather than buried ─────────────────────────────────────────

#: Inter-sensor gap at or below which arrivals count as one coordinated burst.
COORDINATED_WINDOW = timedelta(hours=24)
#: Gap at or above which repeat sightings are treated as unrelated background scanning.
BACKGROUND_GAP = timedelta(days=14)
#: Lag below this between consecutive sensors reads as effectively simultaneous.
SIMULTANEOUS_LAG = timedelta(minutes=5)

#: Interactive SSH clients. A human drove these; bots use libraries.
INTERACTIVE_CLIENTS = ("putty", "openssh_for_windows", "winscp", "securecrt", "mobaxterm")
#: Library and language clients, i.e. scripted automation.
AUTOMATION_HINTS = ("libssh", "paramiko", "go", "asyncssh", "phpseclib", "russh", "libssh2")


@dataclass
class Finding:
    """A result that carries its own evidence."""

    label: str
    detail: str
    count: int
    evidence: list[str] = field(default_factory=list)
    attack: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "detail": self.detail,
            "count": self.count,
            "evidence": self.evidence[:12],
            "attck": self.attack,
        }


# ── Command classification ──────────────────────────────────────────────────────
# Ordered: the first pattern that matches wins, so specific rules precede generic.
# Phases follow the IoT attack-lifecycle shape used in the honeypot literature
# (discover, enter, profile the host, prepare it, fetch payload, install, persist,
# clean up, act) rather than a generic enterprise kill chain.

COMMAND_RULES: list[tuple[str, str, str, str]] = [
    # (regex, lifecycle phase, ATT&CK technique, human label)
    (r"lspci|lshw|nvidia-smi|/dev/nvidia|VGA|\b3D\b", "Profile host",
     "T1082", "GPU enumeration (cryptomining reconnaissance)"),
    (r"\bnproc\b|cpuinfo|lscpu|\bcpu MHz\b", "Profile host",
     "T1082", "CPU enumeration (cryptomining reconnaissance)"),
    (r"free\s+-[mgh]|/proc/meminfo|\bmemtotal\b", "Profile host",
     "T1082", "Memory enumeration"),
    (r"\buname\b|/proc/version|\bhostnamectl\b|\bos-release\b", "Profile host",
     "T1082", "System information discovery"),
    (r"/proc/uptime|\buptime\b", "Profile host", "T1082", "Uptime discovery"),
    (r"chattr\s+-[ia]+|lockr\s+-[ia]+", "Prepare host",
     "T1222", "Removing file immutability to enable tampering"),
    (r"authorized_keys|\.ssh|ssh-rsa|ssh-ed25519", "Persist",
     "T1098.004", "SSH authorized-keys persistence"),
    (r"chpasswd|passwd\s+root|usermod|useradd|adduser", "Persist",
     "T1098", "Account manipulation"),
    (r"\bsudo\s+-S\b|\|\s*sudo\b", "Escalate",
     "T1548.003", "Sudo abuse using a guessed password"),
    (r"\bcrontab\b|/etc/cron|systemctl\s+enable|rc\.local", "Persist",
     "T1053.003", "Scheduled-task persistence"),
    (r"\bwget\b|\bcurl\b|tftp|\bftpget\b", "Fetch payload",
     "T1105", "Ingress tool transfer"),
    (r"\bchmod\b\s*\+?x|\bchmod\b\s*7", "Install",
     "T1222.002", "Making a payload executable"),
    (r"\bhistory\b\s*-c|\.bash_history|\brm\s+-rf\b", "Clean up",
     "T1070", "Indicator removal"),
    (r"iptables|ufw\s+disable|firewalld", "Evade",
     "T1562.004", "Disabling host firewall"),
    (r"\bkill(all)?\b|\bpkill\b|\bps\s+(-|aux)", "Act",
     "T1057", "Process discovery or termination"),
    (r"xmrig|minerd|stratum\+tcp|monero|\bmining\b", "Act",
     "T1496", "Resource hijacking (cryptomining)"),
    (r"\btype\s+type\b|\becho\s+-e\b|\bwhich\b", "Profile host",
     "T1082", "Shell capability probe"),
]

_COMPILED = [(re.compile(p, re.I), phase, tech, label) for p, phase, tech, label in COMMAND_RULES]


def classify_command(cmd: str) -> tuple[str, str, str] | None:
    """Return (phase, ATT&CK technique, label) for a command, or None if unmatched."""
    for pattern, phase, tech, label in _COMPILED:
        if pattern.search(cmd):
            return phase, tech, label
    return None


# ── Analyses ────────────────────────────────────────────────────────────────────


def coordination(db: Session, *, limit: int | None = 40) -> dict[str, Any]:
    """
    Classify multi-sensor addresses by the shape of their inter-sensor lag.

    This is the cross-sensor attribution question: not *whether* an address hit
    several sensors, but whether the timing looks like one scanner walking a range,
    a botnet arriving in parallel, or unrelated background noise.
    """
    rows = db.execute(
        select(Event.src_ip, VpsSource.alias, func.min(Event.occurred_at), func.count(Event.id))
        .join(VpsSource, Event.vps_id == VpsSource.id)
        .group_by(Event.src_ip, VpsSource.alias)
    ).all()

    per_ip: dict[str, list[tuple[str, Any, int]]] = defaultdict(list)
    for ip, alias, first_seen, count in rows:
        per_ip[str(ip)].append((alias, first_seen, count))

    verdicts: Counter[str] = Counter()
    detail: list[dict[str, Any]] = []

    for ip, sightings in per_ip.items():
        if len(sightings) < 2:
            continue
        sightings.sort(key=lambda s: s[1])
        span = sightings[-1][1] - sightings[0][1]
        lags = [
            sightings[i + 1][1] - sightings[i][1] for i in range(len(sightings) - 1)
        ]
        max_lag = max(lags)

        if span >= BACKGROUND_GAP:
            verdict = "background scanning"
        elif max_lag <= SIMULTANEOUS_LAG:
            verdict = "parallel (distributed)"
        elif span <= COORDINATED_WINDOW:
            verdict = "sequential sweep"
        else:
            verdict = "recurring visitor"

        verdicts[verdict] += 1
        detail.append(
            {
                "ip": ip,
                "verdict": verdict,
                "sensors": [s[0] for s in sightings],
                "order": [s[0] for s in sightings],
                "span_seconds": int(span.total_seconds()),
                "max_lag_seconds": int(max_lag.total_seconds()),
                "events": sum(s[2] for s in sightings),
            }
        )

    detail.sort(key=lambda d: (-d["events"], d["span_seconds"]))
    return {
        "multi_sensor_addresses": len(detail),
        "verdicts": dict(verdicts),
        "addresses": detail if limit is None else detail[:limit],
    }


def client_fingerprints(db: Session) -> dict[str, Any]:
    """Group SSH client version strings into automation, interactive, and unknown."""
    rows = db.execute(
        select(
            Event.raw_payload["Client"].astext.label("client"),
            func.count(Event.id),
            func.count(func.distinct(Event.src_ip)),
        )
        .where(Event.raw_payload["Client"].astext.isnot(None))
        .where(Event.raw_payload["Client"].astext != "")
        .group_by("client")
        .order_by(func.count(Event.id).desc())
    ).all()

    def bucket(client: str) -> str:
        low = client.lower()
        if any(h in low for h in INTERACTIVE_CLIENTS):
            return "interactive (likely human)"
        if any(h in low for h in AUTOMATION_HINTS):
            return "automation (library/scripted)"
        return "other"

    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"events": 0, "addresses": 0, "clients": []}
    )
    listing = []
    for client, events, addrs in rows:
        b = bucket(client)
        grouped[b]["events"] += events
        grouped[b]["addresses"] += addrs
        grouped[b]["clients"].append(client)
        listing.append(
            {"client": client, "events": events, "addresses": addrs, "bucket": b}
        )

    total = sum(g["events"] for g in grouped.values()) or 1
    for g in grouped.values():
        g["share"] = round(100 * g["events"] / total, 2)
        g["clients"] = g["clients"][:15]

    return {"buckets": dict(grouped), "clients": listing[:40], "total_events": total}


def credential_ladders(db: Session, *, min_len: int = 4, limit: int = 25) -> dict[str, Any]:
    """
    Extract the ordered password sequence per source, then find shared ladders.

    A ladder repeated verbatim across sources is a tool signature: the same wordlist
    in the same order means the same software, which is a far stronger attribution
    signal than a shared single credential.
    """
    rows = db.execute(
        select(Event.src_ip, Event.username_tried, Event.password_tried, Event.occurred_at)
        .where(Event.password_tried.isnot(None))
        .where(Event.password_tried != "")
        .order_by(Event.src_ip, Event.occurred_at)
    ).all()

    ladders: dict[str, list[str]] = defaultdict(list)
    users: dict[str, set[str]] = defaultdict(set)
    for ip, user, pwd, _ts in rows:
        ladders[str(ip)].append(pwd)
        if user:
            users[str(ip)].add(user)

    # Signature = the ordered ladder, capped so one long session does not dominate.
    signatures: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for ip, seq in ladders.items():
        if len(seq) < min_len:
            continue
        signatures[tuple(seq[:25])].append(ip)

    shared = [
        {
            "ladder": list(sig)[:12],
            "ladder_length": len(sig),
            "addresses": ips[:20],
            "address_count": len(ips),
        }
        for sig, ips in signatures.items()
        if len(ips) > 1
    ]
    shared.sort(key=lambda s: (-s["address_count"], -s["ladder_length"]))

    return {
        "sources_with_ladders": len(signatures),
        "shared_ladder_groups": len(shared),
        "groups": shared[:limit],
        "top_passwords": Counter(r[2] for r in rows).most_common(20),
        "top_usernames": Counter(r[1] for r in rows if r[1]).most_common(20),
    }


def guessing_style(db: Session, *, limit: int = 25) -> dict[str, Any]:
    """
    Separate guessing from spraying from stuffing by account/password fan-out.

    Many passwords against one account is T1110.001. Few passwords across many
    accounts is T1110.003. Roughly one password per account, at volume, looks like
    T1110.004 credential stuffing.
    """
    rows = db.execute(
        select(
            Event.src_ip,
            func.count(func.distinct(Event.username_tried)),
            func.count(func.distinct(Event.password_tried)),
            func.count(Event.id),
        )
        .where(Event.password_tried.isnot(None))
        .where(Event.password_tried != "")
        .group_by(Event.src_ip)
    ).all()

    styles: Counter[str] = Counter()
    detail = []
    for ip, n_users, n_pwds, attempts in rows:
        if attempts < 3:
            style, tech = "probe", None
        elif n_users <= 2 and n_pwds >= 5:
            style, tech = "password guessing", "T1110.001"
        elif n_users >= 5 and n_pwds <= 3:
            style, tech = "password spraying", "T1110.003"
        elif n_users >= 5 and abs(n_users - n_pwds) <= max(2, n_users * 0.2):
            style, tech = "credential stuffing", "T1110.004"
        else:
            style, tech = "mixed brute force", "T1110"
        styles[style] += 1
        detail.append(
            {
                "ip": str(ip),
                "style": style,
                "attck": tech,
                "usernames": n_users,
                "passwords": n_pwds,
                "attempts": attempts,
            }
        )

    detail.sort(key=lambda d: -d["attempts"])
    return {"styles": dict(styles), "sources": detail[:limit]}


def command_phases(db: Session) -> dict[str, Any]:
    """Map observed commands onto lifecycle phases and ATT&CK techniques."""
    rows = db.execute(
        select(
            Event.raw_payload["Command"].astext.label("cmd"),
            Event.src_ip,
            func.count(Event.id).label("n"),
        )
        .where(Event.raw_payload["Command"].astext.isnot(None))
        .where(Event.raw_payload["Command"].astext != "")
        .group_by("cmd", Event.src_ip)
    ).all()

    phases: dict[str, Finding] = {}
    techniques: Counter[str] = Counter()
    unmatched: Counter[str] = Counter()
    label_totals: dict[str, Counter] = defaultdict(Counter)
    total = 0
    sources_by_phase: dict[str, set[str]] = defaultdict(set)

    for cmd, ip, n in rows:
        total += n
        hit = classify_command(cmd)
        if hit is None:
            unmatched[cmd[:90]] += n
            continue
        phase, tech, label = hit
        techniques[tech] += n
        sources_by_phase[phase].add(str(ip))
        f = phases.get(phase)
        if f is None:
            f = phases[phase] = Finding(label=phase, detail=label, count=0, attack=tech)
        f.count += n
        # Keep the highest-volume technique and label as the phase's headline.
        label_totals[phase][(tech, label)] += n
        if len(f.evidence) < 12 and cmd[:110] not in f.evidence:
            f.evidence.append(cmd[:110])

    ordered = [
        "Profile host", "Escalate", "Prepare host", "Fetch payload",
        "Install", "Persist", "Evade", "Clean up", "Act",
    ]
    result = []
    for name in ordered:
        f = phases.get(name)
        if f:
            if label_totals[name]:
                (top_tech, top_label), _ = label_totals[name].most_common(1)[0]
                f.attack, f.detail = top_tech, top_label
            d = f.as_dict()
            d["sources"] = len(sources_by_phase[name])
            d["techniques"] = [
                {"attck": t, "label": lab, "count": c}
                for (t, lab), c in label_totals[name].most_common()
            ]
            result.append(d)

    return {
        "total_command_events": total,
        "classified": sum(f.count for f in phases.values()),
        "phases": result,
        "techniques": techniques.most_common(),
        "unmatched_top": unmatched.most_common(15),
    }


def rhythm(db: Session) -> dict[str, Any]:
    """Hour-of-day activity, and a flatness score standing in for automation."""
    rows = db.execute(
        select(
            func.extract("hour", Event.occurred_at).label("hr"),
            func.count(Event.id),
        ).group_by("hr").order_by("hr")
    ).all()
    hours = {int(h): int(c) for h, c in rows}
    series = [hours.get(h, 0) for h in range(24)]
    total = sum(series) or 1
    mean = total / 24
    # Coefficient of variation: near zero is flat (automated), higher is peaky.
    var = sum((c - mean) ** 2 for c in series) / 24
    cv = (var ** 0.5) / mean if mean else 0.0
    peak = max(range(24), key=lambda h: series[h])
    trough = min(range(24), key=lambda h: series[h])
    return {
        "by_hour_utc": series,
        "coefficient_of_variation": round(cv, 3),
        # Deliberately cautious. A diurnal shape in traffic that is 94% scripted is
        # more likely the compromised-host population powering down, or campaigns
        # launched in operator working hours, than a human at a keyboard. Client
        # fingerprints are the sounder signal for human presence.
        "reading": "flat, consistent with continuous automation" if cv < 0.35
        else "diurnal: campaign or victim-population schedule, not necessarily human presence",
        "peak_hour_utc": peak,
        "trough_hour_utc": trough,
    }


def http_surface(db: Session, *, limit: int = 25) -> dict[str, Any]:
    """What the HTTP probes were actually looking for."""
    uris = db.execute(
        select(Event.raw_payload["RequestURI"].astext.label("uri"), func.count(Event.id))
        .where(Event.raw_payload["RequestURI"].astext.isnot(None))
        .where(Event.raw_payload["RequestURI"].astext != "")
        .group_by("uri").order_by(func.count(Event.id).desc()).limit(limit)
    ).all()
    agents = db.execute(
        select(Event.raw_payload["UserAgent"].astext.label("ua"), func.count(Event.id))
        .where(Event.raw_payload["UserAgent"].astext.isnot(None))
        .where(Event.raw_payload["UserAgent"].astext != "")
        .group_by("ua").order_by(func.count(Event.id).desc()).limit(limit)
    ).all()
    return {
        "top_paths": [{"uri": u, "count": c} for u, c in uris],
        "top_user_agents": [{"agent": a, "count": c} for a, c in agents],
    }


def overview(db: Session) -> dict[str, Any]:
    """Headline counts, including the real deployment window per sensor."""
    per_sensor = db.execute(
        select(
            VpsSource.alias,
            func.count(Event.id),
            func.min(Event.occurred_at),
            func.max(Event.occurred_at),
            func.count(func.distinct(Event.src_ip)),
        ).join(Event, Event.vps_id == VpsSource.id).group_by(VpsSource.alias)
    ).all()
    return {
        "events": db.scalar(select(func.count(Event.id))) or 0,
        "addresses": db.scalar(select(func.count(func.distinct(Event.src_ip)))) or 0,
        "sensors": [
            {
                "alias": a,
                "events": n,
                "first": str(lo),
                "last": str(hi),
                "days": (hi - lo).days if lo and hi else 0,
                "addresses": ips,
            }
            for a, n, lo, hi, ips in per_sensor
        ],
    }


def full_report(db: Session) -> dict[str, Any]:
    return {
        "overview": overview(db),
        "coordination": coordination(db),
        "clients": client_fingerprints(db),
        "credentials": credential_ladders(db),
        "guessing": guessing_style(db),
        "commands": command_phases(db),
        "rhythm": rhythm(db),
        "http": http_surface(db),
    }


def _print_report() -> None:
    with SessionLocal() as db:
        ov = overview(db)
        print("=" * 74)
        print(f"OVERVIEW  {ov['events']:,} events · {ov['addresses']:,} addresses")
        for s in ov["sensors"]:
            print(f"   {s['alias']}  {s['events']:>7,} events  {s['days']:>3}d  "
                  f"{s['addresses']:>5,} addrs  {s['first'][:10]} → {s['last'][:10]}")

        co = coordination(db)
        print("\n" + "=" * 74)
        print(f"CROSS-SENSOR COORDINATION  {co['multi_sensor_addresses']:,} multi-sensor addresses")
        for verdict, n in sorted(co["verdicts"].items(), key=lambda kv: -kv[1]):
            print(f"   {verdict:<26} {n:>6,}")
        print("   top by volume:")
        for a in co["addresses"][:6]:
            print(f"     {a['ip']:<16} {a['verdict']:<22} {'→'.join(a['order'])}"
                  f"  lag {a['max_lag_seconds']}s  {a['events']} ev")

        cl = client_fingerprints(db)
        print("\n" + "=" * 74)
        print("CLIENT FINGERPRINTS")
        for b, g in sorted(cl["buckets"].items(), key=lambda kv: -kv[1]["events"]):
            print(f"   {b:<32} {g['events']:>8,} ev  {g['share']:>5.2f}%  {g['addresses']:>5,} addrs")
        print("   top clients:")
        for c in cl["clients"][:8]:
            print(f"     {c['client']:<34} {c['events']:>8,}  {c['bucket']}")

        gs = guessing_style(db)
        print("\n" + "=" * 74)
        print("CREDENTIAL ATTACK STYLE (MITRE T1110.x)")
        for s, n in sorted(gs["styles"].items(), key=lambda kv: -kv[1]):
            print(f"   {s:<24} {n:>6,} sources")

        cr = credential_ladders(db)
        print("\n" + "=" * 74)
        print(f"CREDENTIAL LADDERS  {cr['sources_with_ladders']:,} sources · "
              f"{cr['shared_ladder_groups']:,} shared-ladder groups")
        for g in cr["groups"][:5]:
            print(f"   {g['address_count']:>4} addrs share a {g['ladder_length']}-step ladder: "
                  f"{' → '.join(g['ladder'][:6])}")

        cm = command_phases(db)
        print("\n" + "=" * 74)
        print(f"COMMAND PHASES  {cm['total_command_events']:,} command events, "
              f"{cm['classified']:,} classified")
        for p in cm["phases"]:
            print(f"   {p['label']:<15} {p['attck']:<12} {p['count']:>6,} ev  "
                  f"{p['sources']:>4} src  {p['detail']}")
        print("   ATT&CK techniques:", ", ".join(f"{t}({n:,})" for t, n in cm["techniques"][:10]))

        rh = rhythm(db)
        print("\n" + "=" * 74)
        print(f"RHYTHM  cv={rh['coefficient_of_variation']}  {rh['reading']}")
        print(f"   peak {rh['peak_hour_utc']:02d}:00 UTC, trough {rh['trough_hour_utc']:02d}:00 UTC")

        ht = http_surface(db)
        print("\n" + "=" * 74)
        print("HTTP SURFACE  top requested paths")
        for p in ht["top_paths"][:8]:
            print(f"   {p['count']:>6,}  {p['uri'][:64]}")


if __name__ == "__main__":
    _print_report()
