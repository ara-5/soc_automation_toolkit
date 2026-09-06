"""Turn (optionally enriched) alerts into a Markdown, CSV, or HTML report."""

import csv
import io
from pathlib import Path
from typing import List


def _row(enriched: dict) -> dict:
    alert = enriched["alert"]
    geoip = enriched.get("geoip") or {}
    threat_intel = enriched.get("threat_intel")
    return {
        "rule": alert.rule,
        "severity": alert.severity,
        "src_ip": alert.src_ip or "",
        "description": alert.description,
        "first_seen": alert.first_seen.isoformat() if alert.first_seen else "",
        "last_seen": alert.last_seen.isoformat() if alert.last_seen else "",
        "country": geoip.get("country", "") if geoip.get("available") else "",
        "isp": geoip.get("isp", "") if geoip.get("available") else "",
        "threat_verdict": threat_intel.verdict if threat_intel else "unknown",
    }


def generate_markdown_report(enriched_alerts: List[dict]) -> str:
    if not enriched_alerts:
        return "# SOC Alert Report\n\nNo alerts triggered.\n"

    lines = ["# SOC Alert Report", "", f"Total alerts: {len(enriched_alerts)}", ""]
    lines.append("| Severity | Rule | Source IP | Verdict | Country | Description |")
    lines.append("|---|---|---|---|---|---|")
    for enriched in enriched_alerts:
        row = _row(enriched)
        lines.append(
            f"| {row['severity']} | {row['rule']} | {row['src_ip']} | "
            f"{row['threat_verdict']} | {row['country']} | {row['description']} |"
        )
    return "\n".join(lines) + "\n"


def generate_csv_report(enriched_alerts: List[dict]) -> str:
    buffer = io.StringIO()
    fieldnames = [
        "rule",
        "severity",
        "src_ip",
        "description",
        "first_seen",
        "last_seen",
        "country",
        "isp",
        "threat_verdict",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for enriched in enriched_alerts:
        writer.writerow(_row(enriched))
    return buffer.getvalue()


_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>SOC Alert Report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
th {{ background: #222; color: #fff; }}
.high {{ background: #fdd; }}
.medium {{ background: #ffe9b3; }}
.low {{ background: #eef; }}
</style>
</head>
<body>
<h1>SOC Alert Report</h1>
<p>Total alerts: {count}</p>
<table>
<tr><th>Severity</th><th>Rule</th><th>Source IP</th><th>Verdict</th><th>Country</th><th>Description</th></tr>
{rows}
</table>
</body>
</html>
"""


def generate_html_report(enriched_alerts: List[dict]) -> str:
    rows_html = []
    for enriched in enriched_alerts:
        row = _row(enriched)
        rows_html.append(
            f'<tr class="{row["severity"]}">'
            f'<td>{row["severity"]}</td><td>{row["rule"]}</td><td>{row["src_ip"]}</td>'
            f'<td>{row["threat_verdict"]}</td><td>{row["country"]}</td>'
            f'<td>{row["description"]}</td></tr>'
        )
    return _HTML_TEMPLATE.format(count=len(enriched_alerts), rows="\n".join(rows_html))


def write_report(enriched_alerts: List[dict], output_path: str) -> None:
    suffix = Path(output_path).suffix.lower()
    if suffix == ".csv":
        content = generate_csv_report(enriched_alerts)
    elif suffix == ".html":
        content = generate_html_report(enriched_alerts)
    else:
        content = generate_markdown_report(enriched_alerts)
    Path(output_path).write_text(content, encoding="utf-8")
