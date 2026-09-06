"""Enrich alerts with GeoIP and threat-intel context before reporting."""

from typing import List, Optional

import requests

import ioc_lookup
from config import Config
from rules import Alert

GEOIP_URL = "http://ip-api.com/json/{ip}"
GEOIP_FIELDS = "status,message,country,countryCode,isp,org,query"
REQUEST_TIMEOUT = 10


def geoip_lookup(ip: str) -> dict:
    try:
        response = requests.get(
            GEOIP_URL.format(ip=ip),
            params={"fields": GEOIP_FIELDS},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            return {"available": False, "reason": data.get("message", "lookup failed")}
        return {
            "available": True,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "org": data.get("org"),
        }
    except requests.RequestException as exc:
        return {"available": False, "reason": str(exc)}


def enrich_alert(alert: Alert, config: Optional[Config] = None) -> dict:
    config = config or Config()
    enrichment = {"alert": alert, "geoip": None, "threat_intel": None}

    if alert.src_ip:
        enrichment["geoip"] = geoip_lookup(alert.src_ip)
        try:
            enrichment["threat_intel"] = ioc_lookup.lookup(alert.src_ip, config)
        except Exception as exc:  # noqa: BLE001 - enrichment must never crash triage
            enrichment["threat_intel"] = None
            enrichment["threat_intel_error"] = str(exc)

    return enrichment


def enrich_alerts(alerts: List[Alert], config: Optional[Config] = None) -> List[dict]:
    return [enrich_alert(alert, config) for alert in alerts]
