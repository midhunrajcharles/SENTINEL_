"""
SENTINEL: Autonomous Agentic SOC Commander
saia_client.py — Splunk AI Assistant (SAIA) client with cached-query fallback

Shared SAIA client used by SherlockAgent and SageAgent for natural-language
to SPL generation. Tries the live SAIA REST endpoint first
(/services/assistant/v1/generate on the Splunk management port). If that
endpoint is unconfigured, unreachable, or returns nothing usable, falls back
to the cached query templates in app/sentinel/lookups/saia_cached_queries.csv
(registered as [saia_cached_queries_lookup] in transforms.conf), matched on
alert_type + phase.

Dependencies: requests, standard library
"""

from __future__ import annotations

import csv
import logging
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("sentinel.saia_client")

# ---------------------------------------------------------------------------
# Environment variable overrides
# ---------------------------------------------------------------------------

_ENV_SAIA_TOKEN    = "SENTINEL_SAIA_TOKEN"
_ENV_SPLUNK_HOST   = "SENTINEL_SPLUNK_HOST"
_ENV_SPLUNK_PORT   = "SENTINEL_SPLUNK_PORT"
_ENV_SPLUNK_SCHEME = "SENTINEL_SPLUNK_SCHEME"

# app/sentinel/lookups/saia_cached_queries.csv
_CACHE_PATH = Path(__file__).resolve().parent.parent / "lookups" / "saia_cached_queries.csv"

# Default values substituted into {placeholder} tokens left unresolved by context
_TEMPLATE_DEFAULTS = {
    "earliest": "-24h",
    "latest":   "now",
}

_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")


# ---------------------------------------------------------------------------
# Cached query lookup
# ---------------------------------------------------------------------------

class _QueryCache:
    """
    Loads app/sentinel/lookups/saia_cached_queries.csv and matches rows on
    alert_type + phase (with "_default" as a wildcard alert_type). Hot-reloads
    when the file's mtime changes, matching ConfigLoader's behaviour.
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
                log.warning("Unable to load SAIA query cache %s: %s", self._path, exc)

    def best_match(self, alert_type: str, phase: str, question: str = "") -> Optional[Dict[str, str]]:
        """Return the best-matching cache row, or None if nothing matches."""
        self._ensure_loaded()
        candidates = [
            row for row in self._rows
            if row.get("phase") == phase
            and row.get("alert_type") in (alert_type, "_default")
        ]
        if not candidates:
            return None

        # Exact alert_type matches before "_default" wildcard rows.
        candidates.sort(key=lambda r: 0 if r.get("alert_type") == alert_type else 1)

        if question:
            q_lower = question.lower()
            for row in candidates:
                pattern = (row.get("question_pattern") or "").lower()
                if pattern and pattern in q_lower:
                    return row

        return candidates[0]


def _fill_template(template: str, context: Optional[Dict[str, Any]]) -> str:
    """
    Substitute {placeholder} tokens in a cached SPL template using values
    from `context`, falling back to _TEMPLATE_DEFAULTS for common tokens
    (earliest/latest). Unresolvable placeholders are left intact so the
    caller's SPL validation stage can flag them.
    """
    context = context or {}

    def _sub(match: "re.Match[str]") -> str:
        key = match.group(1)
        value = context.get(key)
        if value not in (None, ""):
            return str(value)
        if key in _TEMPLATE_DEFAULTS:
            return _TEMPLATE_DEFAULTS[key]
        return match.group(0)

    return _PLACEHOLDER_RE.sub(_sub, template)


# ---------------------------------------------------------------------------
# SAIA client
# ---------------------------------------------------------------------------

class SAIAClient:
    """
    Splunk AI Assistant client — natural language -> SPL generation.

    Usage::

        saia = SAIAClient.from_config()
        spl = saia.generate_spl(
            "Find lateral movement from this host",
            context={"host": case.affected_host, "earliest": "-48h"},
            phase="phase_c",
            alert_type=case.alert_type,
        )
    """

    _PATH    = "/services/assistant/v1/generate"
    _TIMEOUT = 30

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8089,
        token: str = "",
        scheme: str = "https",
        verify_ssl: bool = False,
        cache_path: Optional[Path] = None,
    ) -> None:
        self._base_url = f"{scheme}://{host}:{port}"
        self._token    = token
        self._verify   = verify_ssl

        session = requests.Session()
        adapter = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.5))
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        self._session = session

        self._cache = _QueryCache(cache_path or _CACHE_PATH)

    @classmethod
    def from_config(cls, config: Any = None) -> "SAIAClient":
        """Build a client from sentinel.conf [splunk]/[saia], with env var overrides."""
        from utils.config_loader import get_config
        cfg = config or get_config()

        host   = os.environ.get(_ENV_SPLUNK_HOST,   cfg.get("splunk", "host",   default="localhost"))
        port   = int(os.environ.get(_ENV_SPLUNK_PORT, cfg.get("splunk", "port", default="8089")))
        scheme = os.environ.get(_ENV_SPLUNK_SCHEME, cfg.get("splunk", "scheme", default="https"))
        token  = os.environ.get(_ENV_SAIA_TOKEN,    cfg.get("saia",   "token",  default=""))
        verify = cfg.get_bool("general", "verify_ssl", default=False)

        return cls(host=host, port=port, token=token, scheme=scheme, verify_ssl=verify)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_spl(
        self,
        question: str,
        context: Optional[Dict[str, Any]] = None,
        phase: str = "",
        alert_type: str = "_default",
    ) -> Optional[str]:
        """
        Return an SPL string for `question`, or None if neither the live
        SAIA endpoint nor the cached templates produced anything usable.

        `phase` (e.g. "phase_b") and `alert_type` (e.g.
        "RANSOMWARE_POWERSHELL_ENCODED") select the cached fallback row when
        the REST call fails; both are optional but required for the cache
        to produce a match.
        """
        spl = self._generate_via_rest(question, context)
        if spl:
            return spl

        return self._generate_via_cache(question, context, phase, alert_type)

    # ------------------------------------------------------------------
    # Live SAIA REST endpoint
    # ------------------------------------------------------------------

    def _generate_via_rest(self, question: str, context: Optional[Dict[str, Any]]) -> Optional[str]:
        if not self._base_url or not self._token:
            return None
        try:
            resp = self._session.post(
                self._base_url + self._PATH,
                json={"question": question, "context": context or {}, "mode": "spl_generation"},
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self._TIMEOUT,
                verify=self._verify,
            )
            if resp.status_code != 200:
                log.debug("SAIA returned HTTP %d", resp.status_code)
                return None
            data = resp.json()
            spl = data.get("spl") or data.get("query") or data.get("result", "")
            spl = spl.strip() if spl else ""
            return spl if len(spl) > 10 else None
        except Exception as exc:
            log.debug("SAIA endpoint unavailable (%s)", exc)
            return None

    # ------------------------------------------------------------------
    # Cached fallback
    # ------------------------------------------------------------------

    def _generate_via_cache(
        self,
        question: str,
        context: Optional[Dict[str, Any]],
        phase: str,
        alert_type: str,
    ) -> Optional[str]:
        if not phase:
            return None

        row = self._cache.best_match(alert_type or "_default", phase, question)
        if row is None:
            return None

        spl = _fill_template(row["spl_template"], context)
        log.info(
            "SAIA fallback: using cached query '%s' for phase=%s alert_type=%s",
            row.get("cache_key"), phase, alert_type,
        )
        return spl
