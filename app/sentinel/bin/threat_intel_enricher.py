"""
SENTINEL: Autonomous Agentic SOC Commander
threat_intel_enricher.py — AbuseIPDB IP reputation client with cached fallback

Shared enrichment client used by Vanguard/Sherlock/Sage when the MCP Server's
enrich_threat_intel tool is unavailable or when a lightweight, direct lookup
is preferred. Tries the live AbuseIPDB v2 "check" endpoint first
(https://api.abuseipdb.com/api/v2/check). If the API key is unconfigured, the
request fails, or the response is rate-limited (HTTP 429), falls back to:

  1. app/sentinel/lookups/ioc_whitelist.csv     (registered as
     [ioc_whitelist_lookup] in transforms.conf) — known-good IOCs.
  2. app/sentinel/lookups/threat_intel_cache.csv (registered as
     [threat_intel_cache_lookup] in transforms.conf) — locally cached
     reputation data for previously-seen IOCs.

If neither source has a match, returns a result with verdict "unknown" so
callers can proceed without enrichment (matching the rule-based fallback
pattern in agent_vanguard.py's _FALLBACK_RULES).

Dependencies: requests, standard library
"""

from __future__ import annotations

import csv
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

log = logging.getLogger("sentinel.threat_intel_enricher")

# ---------------------------------------------------------------------------
# Environment variable overrides
# ---------------------------------------------------------------------------

_ENV_ABUSEIPDB_KEY = "SENTINEL_ABUSEIPDB_API_KEY"

# app/sentinel/lookups/
_LOOKUPS_DIR        = Path(__file__).resolve().parent.parent / "lookups"
_WHITELIST_PATH     = _LOOKUPS_DIR / "ioc_whitelist.csv"
_TI_CACHE_PATH      = _LOOKUPS_DIR / "threat_intel_cache.csv"

_ABUSEIPDB_URL      = "https://api.abuseipdb.com/api/v2/check"
_ABUSEIPDB_TIMEOUT  = 10

# Verdict thresholds for AbuseIPDB's abuseConfidenceScore (0-100)
_MALICIOUS_THRESHOLD  = 75
_SUSPICIOUS_THRESHOLD = 25


# ---------------------------------------------------------------------------
# Local CSV lookups (whitelist + reputation cache)
# ---------------------------------------------------------------------------

class _CsvLookup:
    """
    Loads a lookups/*.csv file keyed on `ioc_value`, hot-reloading when the
    file's mtime changes, matching ConfigLoader's / _QueryCache's behaviour.
    """

    def __init__(self, path: Path) -> None:
        self._path  = path
        self._lock  = threading.Lock()
        self._rows: List[Dict[str, str]] = []
        self._mtime: float = 0.0

    def _ensure_loaded(self) -> None:
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            return
        if mtime == self._mtime and self._rows:
            return
        with self._lock:
            try:
                with open(self._path, newline="", encoding="utf-8") as fh:
                    self._rows = list(csv.DictReader(fh))
                self._mtime = mtime
            except OSError as exc:
                log.warning("Unable to load lookup %s: %s", self._path, exc)

    def find(self, ioc_value: str) -> Optional[Dict[str, str]]:
        self._ensure_loaded()
        for row in self._rows:
            if row.get("ioc_value", "").lower() == ioc_value.lower():
                return row
        return None


# ---------------------------------------------------------------------------
# Threat intel enricher
# ---------------------------------------------------------------------------

class ThreatIntelEnricher:
    """
    AbuseIPDB IP reputation client with whitelist + cached-reputation fallback.

    Usage::

        ti = ThreatIntelEnricher.from_config()
        result = ti.enrich_ip("185.220.101.42")
        if result["verdict"] == "malicious":
            ...
    """

    def __init__(
        self,
        api_key: str = "",
        whitelist_path: Optional[Path] = None,
        cache_path: Optional[Path] = None,
        timeout_s: int = _ABUSEIPDB_TIMEOUT,
    ) -> None:
        self._api_key   = api_key
        self._timeout   = timeout_s
        self._whitelist = _CsvLookup(whitelist_path or _WHITELIST_PATH)
        self._cache     = _CsvLookup(cache_path or _TI_CACHE_PATH)

    @classmethod
    def from_config(cls, config: Any = None) -> "ThreatIntelEnricher":
        """
        Build an enricher from sentinel.conf [integrations]/[threat_intel],
        with env var overrides.
        """
        from utils.config_loader import get_config
        cfg = config or get_config()

        api_key = (
            os.environ.get(_ENV_ABUSEIPDB_KEY)
            or cfg.get("threat_intel", "abuseipdb_api_key", default="")
            or cfg.get("integrations", "ti_token", default="")
            or ""
        )
        timeout_s = cfg.get_int("threat_intel", "abuseipdb_timeout_s", default=_ABUSEIPDB_TIMEOUT)

        return cls(api_key=api_key, timeout_s=timeout_s)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        return bool(self._api_key)

    def enrich_ip(self, ip_address: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Return a reputation result for `ip_address`:

            {
              "ioc_value": "185.220.101.42",
              "ioc_type": "ip",
              "verdict": "malicious" | "suspicious" | "clean" | "whitelisted" | "unknown",
              "abuse_confidence_score": int,
              "total_reports": int,
              "categories": [int, ...],
              "country_code": str,
              "isp": str,
              "source": "abuseipdb" | "whitelist" | "cache" | "none",
              "checked_at": ISO-8601 timestamp,
            }

        Checks the whitelist first; if not whitelisted, tries the live
        AbuseIPDB API, then the local reputation cache, then returns
        verdict "unknown".
        """
        whitelisted = self._whitelist.find(ip_address)
        if whitelisted is not None:
            return self._whitelist_result(ip_address, whitelisted)

        result = self._enrich_via_abuseipdb(ip_address, max_age_days)
        if result is not None:
            return result

        return self._enrich_via_cache(ip_address)

    # ------------------------------------------------------------------
    # Live AbuseIPDB API
    # ------------------------------------------------------------------

    def _enrich_via_abuseipdb(self, ip_address: str, max_age_days: int) -> Optional[Dict[str, Any]]:
        if not self.is_available():
            return None
        try:
            resp = requests.get(
                _ABUSEIPDB_URL,
                params={"ipAddress": ip_address, "maxAgeInDays": max_age_days, "verbose": ""},
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=self._timeout,
            )
            if resp.status_code == 429:
                log.warning("AbuseIPDB rate limit reached; falling back to local cache.")
                return None
            if not resp.ok:
                log.warning("AbuseIPDB returned HTTP %d for %s", resp.status_code, ip_address)
                return None

            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            return {
                "ioc_value":              ip_address,
                "ioc_type":               "ip",
                "verdict":                self._score_to_verdict(score),
                "abuse_confidence_score": score,
                "total_reports":          int(data.get("totalReports", 0)),
                "categories":             self._extract_categories(data),
                "country_code":           data.get("countryCode") or "",
                "isp":                    data.get("isp") or "",
                "source":                 "abuseipdb",
                "checked_at":             _utc_now_iso(),
            }
        except (requests.ConnectionError, requests.Timeout) as exc:
            log.warning("AbuseIPDB unavailable for %s: %s", ip_address, exc)
            return None

    @staticmethod
    def _extract_categories(data: Dict[str, Any]) -> List[int]:
        categories: List[int] = []
        for report in data.get("reports", []) or []:
            for cat in report.get("categories", []) or []:
                if cat not in categories:
                    categories.append(cat)
        return categories

    @staticmethod
    def _score_to_verdict(score: int) -> str:
        if score >= _MALICIOUS_THRESHOLD:
            return "malicious"
        if score >= _SUSPICIOUS_THRESHOLD:
            return "suspicious"
        return "clean"

    # ------------------------------------------------------------------
    # Local fallback (whitelist + reputation cache)
    # ------------------------------------------------------------------

    @staticmethod
    def _whitelist_result(ip_address: str, row: Dict[str, str]) -> Dict[str, Any]:
        return {
            "ioc_value":              ip_address,
            "ioc_type":               row.get("ioc_type", "ip"),
            "verdict":                "whitelisted",
            "abuse_confidence_score": 0,
            "total_reports":          0,
            "categories":             [],
            "country_code":           "",
            "isp":                    "",
            "source":                 "whitelist",
            "checked_at":             _utc_now_iso(),
            "notes":                  row.get("reason", ""),
        }

    def _enrich_via_cache(self, ip_address: str) -> Dict[str, Any]:
        row = self._cache.find(ip_address)
        if row is None:
            log.info("No threat intel available for %s (AbuseIPDB unconfigured/unavailable, no cache hit).", ip_address)
            return {
                "ioc_value":              ip_address,
                "ioc_type":               "ip",
                "verdict":                "unknown",
                "abuse_confidence_score": 0,
                "total_reports":          0,
                "categories":             [],
                "country_code":           "",
                "isp":                    "",
                "source":                 "none",
                "checked_at":             _utc_now_iso(),
            }

        categories_raw = (row.get("categories") or "").strip()
        categories = [int(c) for c in categories_raw.split(",") if c.strip().isdigit()]
        malware_families = [m.strip() for m in (row.get("malware_families") or "").split(",") if m.strip()]

        log.info("Threat intel fallback: using cached reputation for %s (verdict=%s)",
                 ip_address, row.get("verdict", "unknown"))

        return {
            "ioc_value":              ip_address,
            "ioc_type":               row.get("ioc_type", "ip"),
            "verdict":                row.get("verdict", "unknown"),
            "abuse_confidence_score": int(row.get("abuse_confidence_score") or 0),
            "total_reports":          int(row.get("total_reports") or 0),
            "categories":             categories,
            "malware_families":       malware_families,
            "country_code":           row.get("country_code", ""),
            "isp":                    row.get("isp", ""),
            "source":                 "cache",
            "checked_at":             _utc_now_iso(),
            "notes":                  row.get("notes", ""),
        }


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
