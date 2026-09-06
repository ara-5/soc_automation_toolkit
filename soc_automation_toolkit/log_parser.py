"""Log ingestion: turn CSV / JSON / SSH auth-log lines into a common
normalized event shape that rules.py can operate on:

    {
        "timestamp": datetime,
        "src_ip": str | None,
        "user": str | None,
        "event": str | None,     # e.g. "login", "connection"
        "status": str | None,    # e.g. "success", "failure"
        "dest_port": int | None,
    }
"""

import csv
import json
import re
from datetime import datetime
from pathlib import Path

_FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "date", "ts", "@timestamp"],
    "src_ip": ["src_ip", "source_ip", "ip", "srcip", "source"],
    "user": ["user", "username", "account"],
    "event": ["event", "event_type", "action"],
    "status": ["status", "result", "outcome"],
    "dest_port": ["dest_port", "port", "dst_port", "destination_port"],
}

_TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
    "%m/%d/%Y %H:%M:%S",
]

_AUTH_LOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd\[\d+\]:\s+(?P<result>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)


class LogParseError(Exception):
    """Raised when a log file cannot be parsed at all."""


def _parse_timestamp(value: str) -> datetime:
    value = value.strip()
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise LogParseError(f"Unrecognized timestamp format: {value!r}")


def _lookup_field(row: dict, canonical: str) -> str | None:
    lowered = {k.lower(): v for k, v in row.items()}
    for alias in _FIELD_ALIASES[canonical]:
        if alias in lowered and lowered[alias] not in (None, ""):
            return lowered[alias]
    return None


def _normalize_row(row: dict) -> dict:
    timestamp_raw = _lookup_field(row, "timestamp")
    dest_port_raw = _lookup_field(row, "dest_port")
    return {
        "timestamp": _parse_timestamp(timestamp_raw) if timestamp_raw else None,
        "src_ip": _lookup_field(row, "src_ip"),
        "user": _lookup_field(row, "user"),
        "event": _lookup_field(row, "event"),
        "status": _lookup_field(row, "status"),
        "dest_port": int(dest_port_raw) if dest_port_raw else None,
    }


def parse_csv(text: str) -> list[dict]:
    reader = csv.DictReader(text.splitlines())
    return [_normalize_row(row) for row in reader if any(row.values())]


def parse_json(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    if text[0] == "[":
        rows = json.loads(text)
    else:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [_normalize_row(row) for row in rows]


def parse_auth_log(text: str) -> list[dict]:
    entries = []
    now_year = datetime.now().year
    for line in text.splitlines():
        match = _AUTH_LOG_RE.search(line)
        if not match:
            continue
        timestamp = datetime.strptime(
            f"{now_year} {match['month']} {match['day']} {match['time']}",
            "%Y %b %d %H:%M:%S",
        )
        entries.append(
            {
                "timestamp": timestamp,
                "src_ip": match["src_ip"],
                "user": match["user"],
                "event": "login",
                "status": "success" if match["result"] == "Accepted" else "failure",
                "dest_port": int(match["port"]),
            }
        )
    return entries


def parse_log(path: str, log_format: str = "auto") -> list[dict]:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8", errors="replace")

    if log_format == "auto":
        suffix = file_path.suffix.lower()
        if suffix == ".csv":
            log_format = "csv"
        elif suffix in (".json", ".jsonl"):
            log_format = "json"
        else:
            log_format = "syslog"

    if log_format == "csv":
        entries = parse_csv(text)
    elif log_format == "json":
        entries = parse_json(text)
    elif log_format == "syslog":
        entries = parse_auth_log(text)
    else:
        raise LogParseError(f"Unsupported log format: {log_format}")

    entries = [e for e in entries if e.get("timestamp") is not None]
    entries.sort(key=lambda e: e["timestamp"])
    return entries
