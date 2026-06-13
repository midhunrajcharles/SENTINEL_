"""
SENTINEL: Autonomous Agentic SOC Commander
hosted_model_client.py — Foundation-Sec hosted model client

Shared client for calling Foundation-Sec-1.1-8B-Instruct via Splunk AI
Toolkit's hosted model REST API
(``/services/ml/models/foundation-sec-1.1-8b-instruct/predict``).

Implements the resilience behaviour described in docs/HOSTED_MODELS.md:
  - exponential backoff on 429/503 (base 2s, max 30s, 3 attempts)
  - per-run response caching for identical prompts
  - raises HostedModelUnavailable when the endpoint/token are unconfigured
    or retries are exhausted, so callers (Vanguard/Sherlock/Executor/Sage)
    can apply their own rule-based fallback — see _FALLBACK_RULES in
    agent_vanguard.py for the established pattern.

Dependencies: requests, standard library
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Optional

import requests

log = logging.getLogger("sentinel.hosted_model_client")

# ---------------------------------------------------------------------------
# Environment variable overrides
# ---------------------------------------------------------------------------

_ENV_MODEL_TOKEN   = "SENTINEL_HOSTED_MODEL_TOKEN"
_ENV_SPLUNK_HOST   = "SENTINEL_SPLUNK_HOST"
_ENV_SPLUNK_PORT   = "SENTINEL_SPLUNK_PORT"
_ENV_SPLUNK_SCHEME = "SENTINEL_SPLUNK_SCHEME"

_DEFAULT_MODEL_NAME = "foundation-sec-1.1-8b-instruct"

# Retry/backoff parameters (docs/HOSTED_MODELS.md "API Rate Limits and Caching Strategies")
_RETRY_STATUS_CODES = (429, 503)
_MAX_ATTEMPTS        = 3
_BACKOFF_BASE_S      = 2.0
_BACKOFF_MAX_S       = 30.0

# <repo_root>/models/prompts/
_PROMPTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "models" / "prompts"

_CACHE_MAXSIZE = 128


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class HostedModelError(Exception):
    """Base exception for hosted model failures."""


class HostedModelUnavailable(HostedModelError):
    """Raised when the model endpoint/token are unconfigured or retries are exhausted."""


class HostedModelResponseError(HostedModelError):
    """Raised on a non-retryable error (auth failure, bad endpoint, malformed output)."""


# ---------------------------------------------------------------------------
# Simple per-run LRU cache
# ---------------------------------------------------------------------------

class _LRUCache:
    """Small OrderedDict-based LRU cache, scoped to one client instance / run."""

    def __init__(self, maxsize: int = _CACHE_MAXSIZE) -> None:
        self._maxsize = maxsize
        self._data: "OrderedDict[str, Any]" = OrderedDict()

    def get(self, key: str) -> Any:
        if key not in self._data:
            return None
        self._data.move_to_end(key)
        return self._data[key]

    def put(self, key: str, value: Any) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        while len(self._data) > self._maxsize:
            self._data.popitem(last=False)


# ---------------------------------------------------------------------------
# Hosted model client
# ---------------------------------------------------------------------------

class HostedModelClient:
    """
    Client for the Foundation-Sec-1.1-8B-Instruct hosted model.

    Usage::

        client = HostedModelClient.from_config(agent_name="vanguard")
        try:
            decision = client.generate_json(user_content=model_input)
        except HostedModelUnavailable:
            decision = _fallback_classification(...)
    """

    def __init__(
        self,
        endpoint: str,
        token: str,
        system_prompt: str = "",
        max_tokens: int = 1024,
        temperature: float = 0.1,
        top_p: float = 0.9,
        timeout_s: float = 30.0,
        verify_ssl: bool = False,
    ) -> None:
        self._endpoint      = endpoint
        self._token         = token
        self._system_prompt = system_prompt
        self._max_tokens    = max_tokens
        self._temperature   = temperature
        self._top_p         = top_p
        self._timeout       = timeout_s
        self._verify        = verify_ssl
        self._cache         = _LRUCache()

    @classmethod
    def from_config(
        cls,
        config: Any = None,
        agent_name: str = "",
        model_name: str = _DEFAULT_MODEL_NAME,
    ) -> "HostedModelClient":
        """
        Build a client from sentinel.conf [general]/[hosted_models], with env
        var overrides. If `agent_name` is given, the matching system prompt
        is loaded from models/prompts/<agent_name>_system_prompt.txt.
        """
        from utils.config_loader import get_config
        cfg = config or get_config()

        host   = os.environ.get(_ENV_SPLUNK_HOST,   cfg.get("general", "splunk_host",   default="localhost"))
        port   = cfg.get_int("general", "splunk_port", default=8089)
        if os.environ.get(_ENV_SPLUNK_PORT):
            port = int(os.environ[_ENV_SPLUNK_PORT])
        scheme = os.environ.get(_ENV_SPLUNK_SCHEME, cfg.get("general", "splunk_scheme", default="https"))

        endpoint = cfg.get("hosted_models", "foundation_sec_endpoint", default="")
        if not endpoint:
            endpoint = f"{scheme}://{host}:{port}/services/ml/models/{model_name}/predict"

        token = (
            os.environ.get(_ENV_MODEL_TOKEN)
            or cfg.get("hosted_models", "api_token", default="")
            or cfg.get("splunk", "api_token", default="")
            or ""
        )

        max_tokens  = cfg.get_int("hosted_models", "foundation_sec_max_tokens", default=1024)
        temperature = float(cfg.get("hosted_models", "foundation_sec_temperature", default="0.1"))
        timeout_s   = float(cfg.get("hosted_models", "foundation_sec_timeout_s", default="30"))
        verify_ssl  = cfg.get_bool("general", "verify_ssl", default=False)

        system_prompt = ""
        if agent_name:
            prompt_path = _PROMPTS_DIR / f"{agent_name}_system_prompt.txt"
            try:
                system_prompt = prompt_path.read_text(encoding="utf-8")
            except OSError as exc:
                log.warning("Could not load system prompt %s: %s", prompt_path, exc)

        return cls(
            endpoint=endpoint,
            token=token,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout_s=timeout_s,
            verify_ssl=verify_ssl,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        return bool(self._endpoint and self._token)

    def generate_text(
        self,
        user_content: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Call Foundation-Sec and return the raw generated text.

        Raises HostedModelUnavailable if unconfigured or retries exhaust on
        429/503; raises HostedModelResponseError on other failures.
        """
        if not self.is_available():
            raise HostedModelUnavailable("Foundation-Sec endpoint/token not configured.")

        payload = {
            "inputs": [
                {"role": "system", "content": system_prompt if system_prompt is not None else self._system_prompt},
                {"role": "user",   "content": user_content},
            ],
            "parameters": {
                "max_new_tokens": max_tokens if max_tokens is not None else self._max_tokens,
                "temperature":    temperature if temperature is not None else self._temperature,
                "top_p":          self._top_p,
                "do_sample":      False,
            },
        }
        headers = {
            "Authorization": f"Splunk {self._token}",
            "Content-Type":  "application/json",
        }

        last_exc: Optional[Exception] = None
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                t_start = time.time()
                resp = requests.post(
                    self._endpoint,
                    json=payload,
                    headers=headers,
                    verify=self._verify,
                    timeout=self._timeout,
                )
                latency_ms = int((time.time() - t_start) * 1000)
                log.debug(
                    "Foundation-Sec attempt %d/%d responded in %dms (HTTP %d)",
                    attempt, _MAX_ATTEMPTS, latency_ms, resp.status_code,
                )

                if resp.status_code == 401:
                    raise HostedModelResponseError(
                        "Foundation-Sec authentication failed — check hosted model token."
                    )
                if resp.status_code == 404:
                    raise HostedModelResponseError(
                        "Foundation-Sec endpoint not found. "
                        "Verify Splunk AI Toolkit is installed and the model name is correct."
                    )
                if resp.status_code in _RETRY_STATUS_CODES:
                    last_exc = HostedModelUnavailable(
                        f"Foundation-Sec returned HTTP {resp.status_code}"
                    )
                    self._sleep_backoff(attempt)
                    continue
                if not resp.ok:
                    raise HostedModelResponseError(
                        f"Foundation-Sec returned HTTP {resp.status_code}: {resp.text[:256]}"
                    )

                return self._extract_text(resp.json())

            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                self._sleep_backoff(attempt)
                continue

        raise HostedModelUnavailable(
            f"Foundation-Sec unavailable after {_MAX_ATTEMPTS} attempts: {last_exc}"
        )

    def generate_json(
        self,
        user_content: Any,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Call Foundation-Sec and parse the response as JSON (stripping any
        markdown code fences). `user_content` is JSON-encoded if not already
        a string.

        Raises HostedModelUnavailable / HostedModelResponseError as per
        generate_text(); raises HostedModelResponseError if the output is
        not valid JSON.
        """
        content = user_content if isinstance(user_content, str) else json.dumps(user_content, indent=2)

        cache_key = None
        if use_cache:
            cache_key = "|".join((
                system_prompt if system_prompt is not None else self._system_prompt,
                content,
                str(max_tokens), str(temperature),
            ))
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        raw_output = self.generate_text(content, system_prompt, max_tokens, temperature)

        raw_output = raw_output.strip()
        if raw_output.startswith("```"):
            raw_output = raw_output.split("```")[1]
            if raw_output.startswith("json"):
                raw_output = raw_output[4:]
            raw_output = raw_output.strip()

        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            raise HostedModelResponseError(
                f"Foundation-Sec output is not valid JSON: {exc}\n"
                f"Raw output (first 500 chars): {raw_output[:500]}"
            ) from exc

        if cache_key is not None:
            self._cache.put(cache_key, parsed)
        return parsed

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_text(raw: Dict[str, Any]) -> str:
        """The AI Toolkit wraps model output in 'outputs' or 'predictions[0].output'."""
        text = (
            raw.get("outputs")
            or (raw.get("predictions") or [{}])[0].get("output", "")
            or (raw.get("predictions") or [{}])[0].get("generated_text", "")
            or ""
        )
        return text

    @staticmethod
    def _sleep_backoff(attempt: int) -> None:
        delay = min(_BACKOFF_BASE_S * (2 ** (attempt - 1)), _BACKOFF_MAX_S)
        log.debug("Backing off %.1fs before retry (attempt %d)", delay, attempt)
        time.sleep(delay)
