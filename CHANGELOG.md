# Changelog

## 0.2.0

- `ai_summary.py`: optional Claude-generated executive summary of a
  triage run (`scan-logs --summarize`), designed against prompt
  injection from log-derived (attacker-controlled) alert data —
  untrusted fields are XML-delimited and escaped, the system prompt
  sets an explicit instruction hierarchy, and the output is
  advisory-only text that never drives control flow.
- `report.py`: HTML report output is now HTML-escaped (previously
  interpolated log-derived fields directly into the page, which was
  an XSS risk for anyone opening the report in a browser).
- Added `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` to `config.py`,
  following the same optional-env-var pattern as the other
  integrations.
- New adversarial test (`test_build_user_prompt_escapes_injection_attempt`)
  exercising a real prompt-injection payload against the summarizer.
- Test suite: 33 → 39 cases.

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
