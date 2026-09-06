# Changelog

## 0.1.0

Initial release.

- `lookup` command: IOC classification (ip/domain/hash) and lookup
  against VirusTotal and AbuseIPDB with a combined verdict.
- `scan-logs` command: CSV/JSON/SSH-auth-log parsing, brute-force /
  port-scan / known-bad-IP detection rules, GeoIP + threat-intel
  enrichment, and Markdown/CSV/HTML reporting.
- Packaged with `pyproject.toml`, installable via `pip install -e .`,
  console script `soc-toolkit`.
- 33-case pytest suite (network calls mocked) with coverage reporting.
- Ruff linting and GitHub Actions CI across Python 3.10–3.12.
- MIT license.
