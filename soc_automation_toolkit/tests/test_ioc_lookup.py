from unittest.mock import Mock, patch

import ioc_lookup
from config import Config


def test_detect_indicator_type_ip():
    assert ioc_lookup.detect_indicator_type("8.8.8.8") == "ip"


def test_detect_indicator_type_domain():
    assert ioc_lookup.detect_indicator_type("example.com") == "domain"


def test_detect_indicator_type_hash():
    assert ioc_lookup.detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert (
        ioc_lookup.detect_indicator_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[:64]
        )
        == "hash"
    )


def test_detect_indicator_type_unknown():
    assert ioc_lookup.detect_indicator_type("not a valid indicator!!") == "unknown"


def _mock_response(json_data, status_code=200):
    resp = Mock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.raise_for_status = Mock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = Exception("http error")
    return resp


@patch("ioc_lookup.requests.get")
def test_query_virustotal_malicious(mock_get):
    mock_get.return_value = _mock_response(
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60},
                    "reputation": -10,
                }
            }
        }
    )
    result = ioc_lookup.query_virustotal("1.2.3.4", "ip", "fake-key")
    assert result["found"] is True
    assert result["verdict"] == "malicious"
    assert result["malicious"] == 5


@patch("ioc_lookup.requests.get")
def test_query_virustotal_not_found(mock_get):
    mock_get.return_value = _mock_response({}, status_code=404)
    result = ioc_lookup.query_virustotal("1.2.3.4", "ip", "fake-key")
    assert result == {"found": False}


@patch("ioc_lookup.requests.get")
def test_query_abuseipdb_clean(mock_get):
    mock_get.return_value = _mock_response(
        {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US", "isp": "Foo"}}
    )
    result = ioc_lookup.query_abuseipdb("1.2.3.4", "fake-key")
    assert result["verdict"] == "clean"


@patch("ioc_lookup.query_abuseipdb")
@patch("ioc_lookup.query_virustotal")
def test_lookup_combines_verdicts(mock_vt, mock_abuse):
    mock_vt.return_value = {"found": True, "verdict": "suspicious"}
    mock_abuse.return_value = {"found": True, "verdict": "malicious"}
    config = Config(vt_api_key="x", abuseipdb_api_key="y")

    result = ioc_lookup.lookup("1.2.3.4", config)

    assert result.verdict == "malicious"
    assert "virustotal" in result.sources
    assert "abuseipdb" in result.sources


def test_lookup_without_api_keys_returns_unknown():
    result = ioc_lookup.lookup("1.2.3.4", Config())
    assert result.verdict == "unknown"
    assert any("VT_API_KEY" in note for note in result.notes)
