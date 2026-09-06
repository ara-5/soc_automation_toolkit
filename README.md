# SOC Automation Toolkit

A small CLI for common SOC analyst chores:

- **IOC lookup** — check an IP, domain, or file hash against VirusTotal and AbuseIPDB.
- **Log parsing & triage** — ingest CSV/JSON/SSH-auth-log logs and flag suspicious
  activity (brute force, port scans, known-bad IPs) using a small rule engine.
- **Enrichment & reporting** — attach GeoIP and threat-intel context to alerts and
  emit a Markdown, CSV, or HTML report.

## Setup

```bash
cd soc_automation_toolkit
python -m venv env
env\Scripts\activate        # on Windows
# source env/bin/activate   # on macOS/Linux
pip install -r requirements-dev.txt
```

Set API keys as environment variables if you want live threat-intel lookups
(both are optional — the toolkit degrades gracefully without them):

```bash
set VT_API_KEY=your-virustotal-key
set ABUSEIPDB_API_KEY=your-abuseipdb-key
```

## Usage

Look up an indicator:

```bash
python soc_automation_toolkit.py lookup 8.8.8.8
python soc_automation_toolkit.py lookup evil.example.com --json
```

Parse a log file, run detection rules, and print a Markdown report:

```bash
python soc_automation_toolkit.py scan-logs samples/sample_auth.csv
```

Same, but with a blocklist, live enrichment, and an HTML report on disk:

```bash
python soc_automation_toolkit.py scan-logs samples/sample_auth.csv \
    --blocklist samples/blocklist.txt --enrich --output report.html
```

Supported log formats: `csv`, `json` (array or JSON Lines), and `syslog`
(SSH auth-log style `Failed password` / `Accepted password` lines). Format is
auto-detected from the file extension, or force it with `--format`.

## Detection rules

| Rule | Trigger |
|---|---|
| `brute_force` | 5+ failed logins from the same source IP within a 10-minute window |
| `port_scan` | a source IP touches 15+ distinct destination ports within 5 minutes |
| `known_bad_ip` | any event from an IP on the supplied `--blocklist` file |

## Running tests

```bash
pytest
```

Tests mock all network calls, so no API keys or internet access are required.
