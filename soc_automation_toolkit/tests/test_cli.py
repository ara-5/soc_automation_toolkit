from pathlib import Path

import soc_automation_toolkit as cli


def test_scan_logs_end_to_end(tmp_path, capsys):
    log_file = tmp_path / "auth.csv"
    log_file.write_text(
        "timestamp,src_ip,user,event,status,dest_port\n"
        "2024-01-01 10:00:00,1.2.3.4,bob,login,failure,22\n"
        "2024-01-01 10:01:00,1.2.3.4,bob,login,failure,22\n"
        "2024-01-01 10:02:00,1.2.3.4,bob,login,failure,22\n"
        "2024-01-01 10:03:00,1.2.3.4,bob,login,failure,22\n"
        "2024-01-01 10:04:00,1.2.3.4,bob,login,failure,22\n"
    )
    report_file = tmp_path / "report.md"

    exit_code = cli.main(["scan-logs", str(log_file), "--output", str(report_file)])

    assert exit_code == 0
    assert report_file.exists()
    content = report_file.read_text()
    assert "brute_force" in content
    assert "1.2.3.4" in content

    out = capsys.readouterr().out
    assert "Parsed 5 log entries" in out
    assert "Triggered 1 alert" in out


def test_lookup_without_keys(capsys):
    exit_code = cli.main(["lookup", "1.2.3.4", "--json"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert '"verdict": "unknown"' in out
