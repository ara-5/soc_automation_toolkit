"""SOC Automation Toolkit CLI.

Commands:
    lookup      Check an IP/domain/hash against VirusTotal / AbuseIPDB.
    scan-logs   Parse a log file, run detection rules, enrich, and report.
"""

import argparse
import json
import sys

import ioc_lookup
import rules
from config import load_config
from enrichment import enrich_alerts
from log_parser import parse_log
from report import generate_markdown_report, write_report


def _cmd_lookup(args: argparse.Namespace) -> int:
    config = load_config()
    result = ioc_lookup.lookup(args.indicator, config)

    if args.json:
        print(
            json.dumps(
                {
                    "indicator": result.indicator,
                    "type": result.indicator_type,
                    "verdict": result.verdict,
                    "sources": result.sources,
                    "notes": result.notes,
                },
                indent=2,
                default=str,
            )
        )
        return 0

    print(f"Indicator : {result.indicator}")
    print(f"Type      : {result.indicator_type}")
    print(f"Verdict   : {result.verdict.upper()}")
    for source, data in result.sources.items():
        print(f"  [{source}] {data}")
    for note in result.notes:
        print(f"  note: {note}")
    return 0


def _cmd_scan_logs(args: argparse.Namespace) -> int:
    entries = parse_log(args.logfile, log_format=args.format)
    print(f"Parsed {len(entries)} log entries from {args.logfile}")

    bad_ips = set()
    if args.blocklist:
        with open(args.blocklist, encoding="utf-8") as f:
            bad_ips = {line.strip() for line in f if line.strip()}

    alerts = rules.run_all_rules(entries, bad_ips=bad_ips)
    print(f"Triggered {len(alerts)} alert(s)")

    config = load_config() if args.enrich else None
    enriched = enrich_alerts(alerts, config) if args.enrich else [
        {"alert": a, "geoip": None, "threat_intel": None} for a in alerts
    ]

    if args.output:
        write_report(enriched, args.output)
        print(f"Report written to {args.output}")
    else:
        print(generate_markdown_report(enriched))

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soc-automation-toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lookup_parser = subparsers.add_parser("lookup", help="Look up an IOC (ip/domain/hash)")
    lookup_parser.add_argument("indicator")
    lookup_parser.add_argument("--json", action="store_true", help="Output raw JSON")
    lookup_parser.set_defaults(func=_cmd_lookup)

    scan_parser = subparsers.add_parser("scan-logs", help="Parse and triage a log file")
    scan_parser.add_argument("logfile")
    scan_parser.add_argument(
        "--format", choices=["auto", "csv", "json", "syslog"], default="auto"
    )
    scan_parser.add_argument("--blocklist", help="Path to a file of known-bad IPs, one per line")
    scan_parser.add_argument(
        "--enrich", action="store_true", help="Enrich alerts with GeoIP/threat intel"
    )
    scan_parser.add_argument("--output", help="Write report to this path (.md/.csv/.html)")
    scan_parser.set_defaults(func=_cmd_scan_logs)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
