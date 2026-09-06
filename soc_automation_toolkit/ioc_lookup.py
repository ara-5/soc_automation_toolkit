"""Indicator-of-compromise (IOC) lookup against VirusTotal / AbuseIPDB.

Supports IPs, domains, and file hashes (md5/sha1/sha256). Network
calls go through `requests` and are isolated in small functions so
tests can mock them without touching the network.
"""

import ipaddress
import re
from dataclasses import dataclass, field

import requests
from config import Config

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

REQUEST_TIMEOUT = 10


class LookupError(Exception):
    """Raised when an IOC lookup cannot be completed."""


def detect_indicator_type(value: str) -> str:
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(value):
        return "hash"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


@dataclass
class LookupResult:
    indicator: str
    indicator_type: str
    verdict: str  # "malicious", "suspicious", "clean", "unknown"
    sources: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)


def _verdict_from_vt_stats(stats: dict) -> str:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "clean"


def query_virustotal(indicator: str, indicator_type: str, api_key: str) -> dict:
    endpoint = {
        "ip": f"{VT_BASE_URL}/ip_addresses/{indicator}",
        "domain": f"{VT_BASE_URL}/domains/{indicator}",
        "hash": f"{VT_BASE_URL}/files/{indicator}",
    }.get(indicator_type)
    if endpoint is None:
        raise LookupError(f"VirusTotal does not support indicator type: {indicator_type}")

    response = requests.get(
        endpoint,
        headers={"x-apikey": api_key},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code == 404:
        return {"found": False}
    response.raise_for_status()

    data = response.json().get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "reputation": attributes.get("reputation"),
        "verdict": _verdict_from_vt_stats(stats),
        "permalink": f"https://www.virustotal.com/gui/search/{indicator}",
    }


def query_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    response = requests.get(
        f"{ABUSEIPDB_BASE_URL}/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": max_age_days},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    data = response.json().get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {
        "found": True,
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports", 0),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "verdict": verdict,
    }


_VERDICT_RANK = {"clean": 0, "unknown": 0, "suspicious": 1, "malicious": 2}


def _combine_verdicts(verdicts) -> str:
    best = "unknown"
    for v in verdicts:
        if _VERDICT_RANK.get(v, 0) > _VERDICT_RANK.get(best, 0):
            best = v
    return best


def lookup(indicator: str, config: Config | None = None) -> LookupResult:
    config = config or Config()
    indicator = indicator.strip()
    indicator_type = detect_indicator_type(indicator)

    result = LookupResult(indicator=indicator, indicator_type=indicator_type, verdict="unknown")

    if indicator_type == "unknown":
        result.notes.append("Could not classify indicator as ip/domain/hash.")
        return result

    verdicts = []

    if indicator_type in ("ip", "domain", "hash") and config.has_virustotal():
        try:
            vt_result = query_virustotal(indicator, indicator_type, config.vt_api_key)
            result.sources["virustotal"] = vt_result
            if vt_result.get("found"):
                verdicts.append(vt_result["verdict"])
        except (requests.RequestException, LookupError) as exc:
            result.notes.append(f"VirusTotal lookup failed: {exc}")
    elif not config.has_virustotal():
        result.notes.append("VT_API_KEY not set; skipped VirusTotal.")

    if indicator_type == "ip":
        if config.has_abuseipdb():
            try:
                abuse_result = query_abuseipdb(indicator, config.abuseipdb_api_key)
                result.sources["abuseipdb"] = abuse_result
                verdicts.append(abuse_result["verdict"])
            except requests.RequestException as exc:
                result.notes.append(f"AbuseIPDB lookup failed: {exc}")
        else:
            result.notes.append("ABUSEIPDB_API_KEY not set; skipped AbuseIPDB.")

    result.verdict = _combine_verdicts(verdicts) if verdicts else "unknown"
    return result
