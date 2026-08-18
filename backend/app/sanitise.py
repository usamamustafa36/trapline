"""
Deployment-identifier scrubbing for attacker-supplied text.

Alias and `base_url` sanitisation in `import_dump` only covers fields *we* control.
It does not cover text the attacker or the decoy itself produced, and that is where
the real leaks were found:

- `payload_excerpt` carries the decoy page title, e.g. the operator's full legal name.
- Generated Sigma rules quote attacker requests verbatim, and those requests carry
  `Host:` headers containing the sensor's real address.

Both reach the published console. So every free-text field is scrubbed on the way into
the database, which means nothing downstream (analytics, detections, exports, the demo
snapshot) can reintroduce an identifier.

Replacements are deliberately readable rather than redacted-to-nothing: an analyst
reading `SENSOR-01 Portal` still learns the event hit a web decoy, without learning
whose.
"""
from __future__ import annotations

import re

# Real sensor addresses -> RFC 5737 documentation ranges, matching the existing map.
IP_MAP = {
    "101.50.107.149": "192.0.2.11",
    "158.69.63.177": "192.0.2.12",
    "203.135.42.52": "192.0.2.13",
    "13.140.175.16": "192.0.2.1",
}

# Longest first, so "Canteen Stores Department" is consumed before a bare "CSD".
ORG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Frontier\s+Works\s+Organi[sz]ation(?:\s+Pakistan)?", re.I), "Sensor 01"),
    (re.compile(r"National\s+Logistics?\s+Cell(?:\s+Pakistan)?", re.I), "Sensor 02"),
    (re.compile(r"Canteen\s+Stores?\s+Department", re.I), "Sensor 03"),
    (re.compile(r"The\s+Caring\s+Store", re.I), "Sensor 03"),
    (re.compile(r"\bFWO\b", re.I), "SENSOR-01"),
    (re.compile(r"\bNLC\b", re.I), "SENSOR-02"),
    (re.compile(r"\bCSD\b", re.I), "SENSOR-03"),
]

_IP_RE = re.compile("|".join(re.escape(ip) for ip in IP_MAP))


def scrub_text(value: str) -> str:
    """Replace deployment identifiers in one string. Returns it unchanged if clean."""
    out = _IP_RE.sub(lambda m: IP_MAP[m.group(0)], value)
    for pattern, replacement in ORG_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def scrub(value):
    """Recursively scrub strings inside dicts, lists and scalars. Keys are scrubbed too."""
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {scrub_text(k) if isinstance(k, str) else k: scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def is_dirty(value: str) -> bool:
    """True if the string still carries an identifier. Used by verification passes."""
    if _IP_RE.search(value):
        return True
    return any(p.search(value) for p, _ in ORG_PATTERNS)
