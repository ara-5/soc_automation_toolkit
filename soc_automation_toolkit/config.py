"""Configuration loading for the SOC automation toolkit.

API keys are read from environment variables so nothing sensitive
ever needs to be committed to the repo:

    VT_API_KEY          - VirusTotal API key
    ABUSEIPDB_API_KEY   - AbuseIPDB API key
    ANTHROPIC_API_KEY   - Claude API key, for `scan-logs --summarize`
    ANTHROPIC_MODEL     - optional, defaults to a small/fast Claude model
"""

import os
from dataclasses import dataclass

DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"


@dataclass
class Config:
    vt_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    anthropic_api_key: str | None = None
    anthropic_model: str = DEFAULT_ANTHROPIC_MODEL

    def has_virustotal(self) -> bool:
        return bool(self.vt_api_key)

    def has_abuseipdb(self) -> bool:
        return bool(self.abuseipdb_api_key)

    def has_anthropic(self) -> bool:
        return bool(self.anthropic_api_key)


def load_config() -> Config:
    return Config(
        vt_api_key=os.environ.get("VT_API_KEY"),
        abuseipdb_api_key=os.environ.get("ABUSEIPDB_API_KEY"),
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"),
        anthropic_model=os.environ.get("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL),
    )
