from datetime import datetime

from report import generate_csv_report, generate_html_report, generate_markdown_report
from rules import Alert


def _enriched():
    alert = Alert(
        rule="brute_force",
        severity="high",
        src_ip="1.2.3.4",
        description="5 failed logins",
        first_seen=datetime(2024, 1, 1, 10, 0, 0),
        last_seen=datetime(2024, 1, 1, 10, 5, 0),
    )
    return [{"alert": alert, "geoip": {"available": True, "country": "US"}, "threat_intel": None}]


def test_generate_markdown_report_empty():
    assert "No alerts triggered" in generate_markdown_report([])


def test_generate_markdown_report_contains_alert():
    md = generate_markdown_report(_enriched())
    assert "brute_force" in md
    assert "1.2.3.4" in md
    assert "US" in md


def test_generate_csv_report_has_header_and_row():
    csv_text = generate_csv_report(_enriched())
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith("rule,severity,src_ip")
    assert "brute_force" in lines[1]


def test_generate_html_report_contains_table_row():
    html = generate_html_report(_enriched())
    assert "<table>" in html
    assert "brute_force" in html
    assert "1.2.3.4" in html
