from datetime import datetime
from unittest.mock import Mock, patch

from enrichment import enrich_alert, geoip_lookup
from rules import Alert


@patch("enrichment.requests.get")
def test_geoip_lookup_success(mock_get):
    resp = Mock()
    resp.raise_for_status = Mock()
    resp.json.return_value = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "isp": "Example ISP",
        "org": "Example Org",
    }
    mock_get.return_value = resp

    result = geoip_lookup("8.8.8.8")
    assert result["available"] is True
    assert result["country"] == "United States"


@patch("enrichment.requests.get")
def test_geoip_lookup_failure_status(mock_get):
    resp = Mock()
    resp.raise_for_status = Mock()
    resp.json.return_value = {"status": "fail", "message": "private range"}
    mock_get.return_value = resp

    result = geoip_lookup("10.0.0.1")
    assert result["available"] is False


@patch("enrichment.ioc_lookup.lookup")
@patch("enrichment.geoip_lookup")
def test_enrich_alert_combines_geoip_and_threat_intel(mock_geoip, mock_lookup):
    mock_geoip.return_value = {"available": True, "country": "US"}
    mock_lookup.return_value = Mock(verdict="malicious")

    alert = Alert(
        rule="brute_force",
        severity="high",
        src_ip="1.2.3.4",
        description="test",
        first_seen=datetime(2024, 1, 1),
        last_seen=datetime(2024, 1, 1),
    )
    enriched = enrich_alert(alert)

    assert enriched["geoip"]["country"] == "US"
    assert enriched["threat_intel"].verdict == "malicious"


def test_enrich_alert_without_src_ip():
    alert = Alert(rule="brute_force", severity="high", src_ip=None, description="test")
    enriched = enrich_alert(alert)
    assert enriched["geoip"] is None
    assert enriched["threat_intel"] is None
