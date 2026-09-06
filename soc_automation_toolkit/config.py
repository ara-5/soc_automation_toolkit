"""Configuration loading for the SOC automation toolkit.

API keys are read from environment variables so nothing sensitive
ever needs to be committed to the repo:

    VT_API_KEY          - VirusTotal API key
    ABUSEIPDB_API_KEY   - AbuseIPDB API key
"""

import os
from dataclasses import dataclass


@dataclass
class Config:
    vt_api_key: str | None = None
    abuseipdb_api_key: str | None = None

    def has_virustotal(self) -> bool:
        return bool(self.vt_api_key)

    def has_abuseipdb(self) -> bool:
        return bool(self.abuseipdb_api_key)


def load_config() -> Config:
    return Config(
        vt_api_key=os.environ.get("VT_API_KEY"),
        abuseipdb_api_key=os.environ.get("ABUSEIPDB_API_KEY"),
    )
