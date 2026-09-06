from datetime import datetime

from log_parser import parse_auth_log, parse_csv, parse_json


def test_parse_csv_basic():
    text = (
        "timestamp,src_ip,user,event,status,dest_port\n"
        "2024-01-01 10:00:00,1.2.3.4,bob,login,failure,22\n"
        "2024-01-01 10:01:00,1.2.3.4,bob,login,success,22\n"
    )
    entries = parse_csv(text)
    assert len(entries) == 2
    assert entries[0]["src_ip"] == "1.2.3.4"
    assert entries[0]["status"] == "failure"
    assert entries[0]["dest_port"] == 22
    assert entries[0]["timestamp"] == datetime(2024, 1, 1, 10, 0, 0)


def test_parse_csv_alias_headers():
    text = "date,source_ip,action,result,port\n2024-01-01 10:00:00,5.6.7.8,login,failure,22\n"
    entries = parse_csv(text)
    assert entries[0]["src_ip"] == "5.6.7.8"
    assert entries[0]["event"] == "login"
    assert entries[0]["status"] == "failure"


def test_parse_json_array():
    text = (
        '[{"timestamp": "2024-01-01T10:00:00", "src_ip": "9.9.9.9", '
        '"event": "connection", "dest_port": 443}]'
    )
    entries = parse_json(text)
    assert len(entries) == 1
    assert entries[0]["src_ip"] == "9.9.9.9"
    assert entries[0]["dest_port"] == 443


def test_parse_json_lines():
    text = (
        '{"timestamp": "2024-01-01T10:00:00", "src_ip": "1.1.1.1"}\n'
        '{"timestamp": "2024-01-01T10:01:00", "src_ip": "2.2.2.2"}\n'
    )
    entries = parse_json(text)
    assert len(entries) == 2


def test_parse_auth_log_failed_and_accepted():
    text = (
        "Jan 10 03:14:15 host sshd[123]: Failed password for invalid user admin "
        "from 203.0.113.5 port 51515 ssh2\n"
        "Jan 10 03:14:20 host sshd[123]: Accepted password for root "
        "from 203.0.113.5 port 51516 ssh2\n"
    )
    entries = parse_auth_log(text)
    assert len(entries) == 2
    assert entries[0]["status"] == "failure"
    assert entries[0]["user"] == "admin"
    assert entries[0]["src_ip"] == "203.0.113.5"
    assert entries[1]["status"] == "success"
    assert entries[1]["user"] == "root"


def test_parse_auth_log_ignores_unmatched_lines():
    text = "some unrelated log line that does not match\n"
    assert parse_auth_log(text) == []
