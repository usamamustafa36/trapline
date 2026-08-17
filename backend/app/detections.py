"""
Turn honeypot observations into detection content a defence stack can consume.

A dashboard tells you what happened. This turns what happened into artefacts you can
deploy: **Sigma** rules for a SIEM, **STIX 2.1** indicators for a threat-intel
platform, and a scored blocklist. That is the step where honeypot telemetry stops
being a study and starts being defence, and it is the gap the adaptive-honeypot
literature names but does not fill.

Two principles hold throughout.

**Every rule carries its evidence.** Each generated rule records how many events and
how many distinct source addresses it was derived from, in the description and in the
`trapline_evidence` block. A reader can judge whether a rule rests on 58 addresses or
on 2, which is the difference between a signature and a coincidence.

**Nothing is invented.** Rules are emitted only from patterns actually observed in the
data. There are no templates waiting to be filled with plausible values.
"""
from __future__ import annotations

import json
import uuid
from datetime import date
from typing import Any

import yaml
from sqlalchemy.orm import Session

from . import analytics

AUTHOR = "Trapline (honeypot-derived)"
NAMESPACE = uuid.UUID("7c1e4d2a-9f83-4b61-8a05-3d6b2e9f1c74")

#: Minimum distinct source addresses before a shared-pattern rule is emitted.
#: Two addresses is a coincidence; this keeps the output defensible.
MIN_ADDRESSES = 3


def _rule_id(seed: str) -> str:
    """Deterministic rule id, so regenerating does not churn identifiers."""
    return str(uuid.uuid5(NAMESPACE, seed))


def _rule(
    *,
    title: str,
    seed: str,
    description: str,
    tags: list[str],
    logsource: dict[str, str],
    detection: dict[str, Any],
    level: str,
    falsepositives: list[str],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "title": title,
        "id": _rule_id(seed),
        "status": "experimental",
        "description": description,
        "author": AUTHOR,
        "date": date.today().strftime("%Y/%m/%d"),
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": falsepositives,
        "level": level,
        # Non-standard block, deliberately namespaced. Sigma consumers ignore unknown
        # top-level keys, and it keeps the provenance attached to the rule itself.
        "trapline_evidence": evidence,
    }


def credential_ladder_rules(report: dict[str, Any]) -> list[dict[str, Any]]:
    """One rule per credential ladder shared by several sources: a tool signature."""
    rules = []
    for group in report["credentials"]["groups"]:
        n = group["address_count"]
        if n < MIN_ADDRESSES:
            continue
        ladder = group["ladder"]
        # The longest credential in the prefix is the most distinctive, so it makes the
        # rule identifiable in a directory of many.
        marker = max(ladder[:8], key=len) if ladder else "unknown"
        marker = marker.strip().strip("-")[:24] or "unknown"
        rules.append(
            _rule(
                title=f"Shared credential ladder '{marker}' observed from {n} sources",
                seed=f"ladder|{'|'.join(ladder)}",
                description=(
                    f"An identical ordered password sequence was attempted by {n} distinct "
                    f"source addresses across the honeypot fleet, over a ladder of "
                    f"{group['ladder_length']} steps. The same wordlist in the same order "
                    "indicates the same tooling rather than independent activity, so this "
                    "matches the tool rather than any single actor."
                ),
                tags=["attack.credential_access", "attack.t1110.001"],
                logsource={"category": "authentication"},
                detection={
                    "selection": {"password|contains": ladder[:8]},
                    "condition": "selection",
                },
                level="medium",
                falsepositives=[
                    "Password-strength auditing or red-team exercises using public wordlists",
                ],
                evidence={
                    "source_addresses": n,
                    "example_addresses": group["addresses"][:10],
                    "ladder_length": group["ladder_length"],
                    "ladder_prefix": ladder[:8],
                },
            )
        )
    return rules


def client_fingerprint_rules(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Rules for SSH client banners: scripted automation, and interactive clients."""
    rules = []
    buckets = report["clients"]["buckets"]
    clients = report["clients"]["clients"]

    automation = [c for c in clients if c["bucket"].startswith("automation")]
    if automation:
        b = buckets.get("automation (library/scripted)", {})
        rules.append(
            _rule(
                title="SSH connection from a scripted client library",
                seed="client|automation",
                description=(
                    "SSH client version strings belonging to programming libraries rather "
                    f"than interactive clients. Observed on {b.get('events', 0):,} events "
                    f"from {b.get('addresses', 0):,} addresses, "
                    f"{b.get('share', 0)}% of all fingerprinted traffic. Legitimate "
                    "automation also uses these libraries, so this is a triage signal "
                    "rather than a finding on its own."
                ),
                tags=["attack.reconnaissance", "attack.t1595"],
                logsource={"category": "network_connection", "service": "ssh"},
                detection={
                    "selection": {
                        "client_version|contains": [c["client"] for c in automation[:12]]
                    },
                    "condition": "selection",
                },
                level="low",
                falsepositives=[
                    "Legitimate automation, CI runners, backup jobs and orchestration tools",
                ],
                evidence={
                    "events": b.get("events", 0),
                    "source_addresses": b.get("addresses", 0),
                    "share_percent": b.get("share", 0),
                    "clients": [c["client"] for c in automation[:12]],
                },
            )
        )

    interactive = [c for c in clients if c["bucket"].startswith("interactive")]
    if interactive:
        b = buckets.get("interactive (likely human)", {})
        rules.append(
            _rule(
                title="Interactive SSH client against an unattended service",
                seed="client|interactive",
                description=(
                    "SSH client banners belonging to interactive GUI clients, which "
                    "indicate a human at a keyboard rather than a script. Observed on "
                    f"{b.get('events', 0):,} events from {b.get('addresses', 0):,} "
                    f"addresses, {b.get('share', 0)}% of fingerprinted traffic. On a "
                    "service that should only ever see automation, this is worth "
                    "escalating."
                ),
                tags=["attack.initial_access", "attack.t1078"],
                logsource={"category": "network_connection", "service": "ssh"},
                detection={
                    "selection": {
                        "client_version|contains": [c["client"] for c in interactive[:12]]
                    },
                    "condition": "selection",
                },
                level="high",
                falsepositives=[
                    "Administrators connecting by hand from a workstation",
                ],
                evidence={
                    "events": b.get("events", 0),
                    "source_addresses": b.get("addresses", 0),
                    "share_percent": b.get("share", 0),
                    "clients": [c["client"] for c in interactive[:12]],
                },
            )
        )
    return rules


def command_rules(report: dict[str, Any]) -> list[dict[str, Any]]:
    """One rule per observed lifecycle phase, keyed on the commands that matched."""
    severity = {
        "Act": "critical",
        "Persist": "high",
        "Escalate": "high",
        "Fetch payload": "high",
        "Install": "high",
        "Evade": "high",
        "Clean up": "medium",
        "Prepare host": "medium",
        "Profile host": "low",
    }
    tactic = {
        "Profile host": "attack.discovery",
        "Escalate": "attack.privilege_escalation",
        "Prepare host": "attack.defense_evasion",
        "Fetch payload": "attack.command_and_control",
        "Install": "attack.execution",
        "Persist": "attack.persistence",
        "Evade": "attack.defense_evasion",
        "Clean up": "attack.defense_evasion",
        "Act": "attack.impact",
    }
    rules = []
    for phase in report["commands"]["phases"]:
        name = phase["label"]
        tech = (phase.get("attck") or "").lower()
        tags = [tactic.get(name, "attack.execution")]
        if tech:
            tags.append(f"attack.{tech}")
        rules.append(
            _rule(
                title=f"Post-compromise shell activity: {phase['detail']}",
                seed=f"command|{name}|{tech}",
                description=(
                    f"Shell commands observed on the honeypot fleet corresponding to the "
                    f"{name.lower()} phase of the attack lifecycle, specifically "
                    f"{phase['detail'].lower()}. Derived from {phase['count']:,} command "
                    f"events across {phase['sources']} distinct source addresses."
                ),
                tags=tags,
                logsource={"category": "process_creation", "product": "linux"},
                detection={
                    "selection": {"CommandLine|contains": phase["evidence"][:8]},
                    "condition": "selection",
                },
                level=severity.get(name, "medium"),
                falsepositives=(
                    ["Routine system administration and inventory collection"]
                    if name == "Profile host"
                    else ["Legitimate configuration management"]
                ),
                evidence={
                    "events": phase["count"],
                    "source_addresses": phase["sources"],
                    "attck": phase.get("attck"),
                    "example_commands": phase["evidence"][:8],
                    "techniques": phase.get("techniques", []),
                },
            )
        )
    return rules


def http_rules(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Rule for the application paths actually probed."""
    paths = [p["uri"] for p in report["http"]["top_paths"] if p["uri"] not in ("/", "/favicon.ico")]
    if not paths:
        return []
    total = sum(p["count"] for p in report["http"]["top_paths"])
    return [
        _rule(
            title="Web application probing of management endpoints",
            seed="http|paths",
            description=(
                "HTTP request paths probed against the honeypot fleet, dominated by "
                "application management interfaces. Derived from "
                f"{total:,} recorded HTTP events."
            ),
            tags=["attack.reconnaissance", "attack.t1595.002", "attack.t1190"],
            logsource={"category": "webserver"},
            detection={"selection": {"cs-uri-stem|contains": paths[:12]}, "condition": "selection"},
            level="medium",
            falsepositives=["Legitimate administrative access to management consoles"],
            evidence={"http_events": total, "paths": paths[:12]},
        )
    ]


def coordination_rules(report: dict[str, Any]) -> list[dict[str, Any]]:
    """A rule listing addresses whose cross-sensor timing indicates coordination."""
    co = report["coordination"]
    coordinated = [
        a for a in co["addresses"]
        if a["verdict"] in ("sequential sweep", "parallel (distributed)")
    ]
    if not coordinated:
        return []
    return [
        _rule(
            title="Source addresses showing coordinated multi-sensor activity",
            seed="coordination|sweep",
            description=(
                "Addresses observed on more than one independent sensor within a short "
                "window, in an ordered sequence or near-simultaneously. The timing shape "
                "distinguishes a directed sweep from ordinary background scanning: "
                f"{co['verdicts'].get('sequential sweep', 0)} sweeps and "
                f"{co['verdicts'].get('parallel (distributed)', 0)} parallel arrivals out "
                f"of {co['multi_sensor_addresses']} multi-sensor addresses."
            ),
            tags=["attack.reconnaissance", "attack.t1595.001"],
            logsource={"category": "firewall"},
            detection={
                "selection": {"src_ip": [a["ip"] for a in coordinated[:40]]},
                "condition": "selection",
            },
            level="high",
            falsepositives=[
                "Security scanning services and research crawlers that survey wide ranges",
            ],
            evidence={
                "multi_sensor_addresses": co["multi_sensor_addresses"],
                "verdicts": co["verdicts"],
                "examples": [
                    {
                        "ip": a["ip"],
                        "order": a["order"],
                        "max_lag_seconds": a["max_lag_seconds"],
                        "events": a["events"],
                    }
                    for a in coordinated[:10]
                ],
            },
        )
    ]


def build_rules(db: Session, report: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """All Sigma rules derivable from the current dataset, highest severity first."""
    report = report or analytics.full_report(db)
    rules = (
        coordination_rules(report)
        + command_rules(report)
        + credential_ladder_rules(report)
        + client_fingerprint_rules(report)
        + http_rules(report)
    )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rules.sort(key=lambda r: order.get(r["level"], 5))
    return rules


def rules_as_yaml(rules: list[dict[str, Any]]) -> str:
    """Multi-document Sigma YAML, the form a rule directory ships in."""
    return "\n".join(
        "---\n" + yaml.safe_dump(r, sort_keys=False, allow_unicode=True, width=100)
        for r in rules
    )


def blocklist(db: Session, report: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Scored blocklist from cross-sensor coordination.

    Confidence reflects the timing verdict, not merely the fact of being seen. This is
    the preemptive step the honeypot literature proposes and does not build; whether it
    actually reduces return traffic is measurable and not yet measured.
    """
    report = report or analytics.full_report(db)
    # The blocklist should cover every coordinated address, not the display slice.
    full = analytics.coordination(db, limit=None)
    report = {**report, "coordination": full}
    weight = {
        "parallel (distributed)": 0.95,
        "sequential sweep": 0.9,
        "recurring visitor": 0.6,
        "background scanning": 0.3,
    }
    entries = [
        {
            "ip": a["ip"],
            "confidence": weight.get(a["verdict"], 0.3),
            "reason": a["verdict"],
            "sensors": a["sensors"],
            "events": a["events"],
        }
        for a in report["coordination"]["addresses"]
    ]
    entries.sort(key=lambda e: (-e["confidence"], -e["events"]))
    high = [e for e in entries if e["confidence"] >= 0.9]
    return {
        "generated": date.today().isoformat(),
        "total": len(entries),
        "high_confidence": len(high),
        "entries": entries,
        "nftables": "\n".join(
            ["table inet trapline {", "  set blocked {", "    type ipv4_addr", "    elements = {"]
            + [f"      {e['ip']}," for e in high]
            + ["    }", "  }", "}"]
        ),
        "note": (
            "Confidence is derived from cross-sensor timing, not from reputation. "
            "Effectiveness is unmeasured: tracking whether blocked sources return is "
            "the evaluation this output makes possible."
        ),
    }


def stix_bundle(db: Session, report: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    STIX 2.1 bundle of indicators and attack patterns.

    Answers the standards gap directly: honeypot observations expressed in a schema a
    threat-intel platform already speaks, at the indicator level rather than only as
    internal state labels.
    """
    report = report or analytics.full_report(db)
    report = {**report, "coordination": analytics.coordination(db, limit=None)}
    now = f"{date.today().isoformat()}T00:00:00.000Z"
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{_rule_id('identity')}",
            "created": now,
            "modified": now,
            "name": "Trapline honeynet",
            "identity_class": "system",
            "description": "Distributed honeypot sensor fleet.",
        }
    ]

    for a in report["coordination"]["addresses"]:
        if a["verdict"] not in ("sequential sweep", "parallel (distributed)"):
            continue
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{_rule_id('ind|' + a['ip'])}",
                "created": now,
                "modified": now,
                "name": f"Coordinated multi-sensor source {a['ip']}",
                "description": (
                    f"Observed on {len(a['sensors'])} sensors in order "
                    f"{' then '.join(a['order'])}, maximum inter-sensor lag "
                    f"{a['max_lag_seconds']}s, {a['events']} events. Verdict: {a['verdict']}."
                ),
                "indicator_types": ["attribution"],
                "pattern": f"[ipv4-addr:value = '{a['ip']}']",
                "pattern_type": "stix",
                "valid_from": now,
                "labels": [a["verdict"].replace(" ", "-")],
            }
        )

    seen_tech: set[str] = set()
    for phase in report["commands"]["phases"]:
        tech = phase.get("attck")
        if not tech or tech in seen_tech:
            continue
        seen_tech.add(tech)
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{_rule_id('ap|' + tech)}",
                "created": now,
                "modified": now,
                "name": phase["detail"],
                "description": (
                    f"Observed in {phase['count']} command events from "
                    f"{phase['sources']} source addresses."
                ),
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech,
                        "url": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/",
                    }
                ],
            }
        )

    return {
        "type": "bundle",
        "id": f"bundle--{_rule_id('bundle|' + now)}",
        "objects": objects,
    }


def _main() -> None:
    from .database import SessionLocal

    with SessionLocal() as db:
        report = analytics.full_report(db)
        rules = build_rules(db, report)
        print(f"# {len(rules)} Sigma rule(s) generated from observed telemetry\n")
        print(rules_as_yaml(rules))
        bl = blocklist(db, report)
        print(f"\n# blocklist: {bl['total']} entries, {bl['high_confidence']} high confidence")
        bundle = stix_bundle(db, report)
        print(f"# STIX bundle: {len(bundle['objects'])} objects")


if __name__ == "__main__":
    _main()
