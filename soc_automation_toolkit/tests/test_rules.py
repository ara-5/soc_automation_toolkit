from datetime import datetime, timedelta

from rules import detect_brute_force, detect_known_bad_ip, detect_port_scan


def _entry(minute, src_ip="1.2.3.4", event="login", status="failure", dest_port=None):
    return {
        "timestamp": datetime(2024, 1, 1, 10, 0, 0) + timedelta(minutes=minute),
        "src_ip": src_ip,
        "user": "bob",
        "event": event,
        "status": status,
        "dest_port": dest_port,
    }


def test_detect_brute_force_triggers_on_threshold():
    entries = [_entry(i) for i in range(5)]
    alerts = detect_brute_force(entries, threshold=5, window=timedelta(minutes=10))
    assert len(alerts) == 1
    assert alerts[0].rule == "brute_force"
    assert alerts[0].src_ip == "1.2.3.4"


def test_detect_brute_force_no_alert_below_threshold():
    entries = [_entry(i) for i in range(4)]
    alerts = detect_brute_force(entries, threshold=5, window=timedelta(minutes=10))
    assert alerts == []


def test_detect_brute_force_outside_window_does_not_trigger():
    entries = [_entry(0), _entry(1), _entry(20), _entry(21), _entry(22)]
    alerts = detect_brute_force(entries, threshold=5, window=timedelta(minutes=10))
    assert alerts == []


def test_detect_brute_force_ignores_successful_logins():
    entries = [_entry(i, status="success") for i in range(5)]
    assert detect_brute_force(entries, threshold=5) == []


def _scan_entry(seconds, src_ip="1.2.3.4", dest_port=None):
    return {
        "timestamp": datetime(2024, 1, 1, 10, 0, 0) + timedelta(seconds=seconds),
        "src_ip": src_ip,
        "user": None,
        "event": "connection",
        "status": None,
        "dest_port": dest_port,
    }


def test_detect_port_scan_triggers():
    entries = [_scan_entry(i * 10, dest_port=1000 + i) for i in range(15)]
    alerts = detect_port_scan(entries, port_threshold=15, window=timedelta(minutes=5))
    assert len(alerts) == 1
    assert alerts[0].rule == "port_scan"


def test_detect_port_scan_no_alert_below_threshold():
    entries = [_scan_entry(i * 10, dest_port=1000 + i) for i in range(5)]
    assert detect_port_scan(entries, port_threshold=15) == []


def test_detect_known_bad_ip():
    entries = [_entry(0, src_ip="6.6.6.6"), _entry(1, src_ip="1.1.1.1")]
    alerts = detect_known_bad_ip(entries, {"6.6.6.6"})
    assert len(alerts) == 1
    assert alerts[0].src_ip == "6.6.6.6"


def test_detect_known_bad_ip_empty_blocklist():
    entries = [_entry(0, src_ip="6.6.6.6")]
    assert detect_known_bad_ip(entries, set()) == []
