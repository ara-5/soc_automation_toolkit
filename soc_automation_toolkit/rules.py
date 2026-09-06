"""Rule-based detections that turn normalized log entries into alerts."""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class Alert:
    rule: str
    severity: str  # "low", "medium", "high"
    src_ip: str | None
    description: str
    evidence: list = field(default_factory=list)
    first_seen: object | None = None
    last_seen: object | None = None


def detect_brute_force(
    entries: Iterable[dict],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> list[Alert]:
    """Flag src_ips with >= threshold failed logins inside a rolling window."""
    failures = defaultdict(list)
    for entry in entries:
        if entry.get("event") == "login" and entry.get("status") == "failure":
            failures[entry.get("src_ip")].append(entry)

    alerts = []
    for src_ip, events in failures.items():
        events.sort(key=lambda e: e["timestamp"])
        window_events = []
        for event in events:
            window_events.append(event)
            window_events = [
                e for e in window_events if event["timestamp"] - e["timestamp"] <= window
            ]
            if len(window_events) >= threshold:
                alerts.append(
                    Alert(
                        rule="brute_force",
                        severity="high",
                        src_ip=src_ip,
                        description=(
                            f"{len(window_events)} failed logins from {src_ip} "
                            f"within {window}"
                        ),
                        evidence=list(window_events),
                        first_seen=window_events[0]["timestamp"],
                        last_seen=window_events[-1]["timestamp"],
                    )
                )
                window_events = []
    return alerts


def detect_port_scan(
    entries: Iterable[dict],
    port_threshold: int = 15,
    window: timedelta = timedelta(minutes=5),
) -> list[Alert]:
    """Flag src_ips that touch many distinct destination ports quickly."""
    connections = defaultdict(list)
    for entry in entries:
        if entry.get("dest_port") is not None:
            connections[entry.get("src_ip")].append(entry)

    alerts = []
    for src_ip, events in connections.items():
        events.sort(key=lambda e: e["timestamp"])
        window_events = []
        for event in events:
            window_events.append(event)
            window_events = [
                e for e in window_events if event["timestamp"] - e["timestamp"] <= window
            ]
            distinct_ports = {e["dest_port"] for e in window_events}
            if len(distinct_ports) >= port_threshold:
                alerts.append(
                    Alert(
                        rule="port_scan",
                        severity="medium",
                        src_ip=src_ip,
                        description=(
                            f"{src_ip} touched {len(distinct_ports)} distinct ports "
                            f"within {window}"
                        ),
                        evidence=list(window_events),
                        first_seen=window_events[0]["timestamp"],
                        last_seen=window_events[-1]["timestamp"],
                    )
                )
                window_events = []
    return alerts


def detect_known_bad_ip(entries: Iterable[dict], bad_ips: set[str]) -> list[Alert]:
    """Flag any entry whose src_ip is on a supplied blocklist."""
    if not bad_ips:
        return []
    matches = defaultdict(list)
    for entry in entries:
        if entry.get("src_ip") in bad_ips:
            matches[entry["src_ip"]].append(entry)

    alerts = []
    for src_ip, events in matches.items():
        events.sort(key=lambda e: e["timestamp"])
        alerts.append(
            Alert(
                rule="known_bad_ip",
                severity="high",
                src_ip=src_ip,
                description=f"{len(events)} event(s) from blocklisted IP {src_ip}",
                evidence=list(events),
                first_seen=events[0]["timestamp"],
                last_seen=events[-1]["timestamp"],
            )
        )
    return alerts


def run_all_rules(entries: list[dict], bad_ips: set[str] | None = None) -> list[Alert]:
    alerts = []
    alerts.extend(detect_brute_force(entries))
    alerts.extend(detect_port_scan(entries))
    alerts.extend(detect_known_bad_ip(entries, bad_ips or set()))
    return alerts
