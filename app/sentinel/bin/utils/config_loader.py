"""
SENTINEL: Autonomous Agentic SOC Commander
config_loader.py — Hierarchical configuration loader

Reads Splunk-style .conf files (INI format) and .json files from two layers:
  1. app/sentinel/default/   — shipped defaults (read-only at runtime)
  2. app/sentinel/local/     — operator overrides (write layer)

Local values silently override defaults, following Splunk's standard precedence
model. Environment variables with the SENTINEL_ prefix override everything.

Files are cached in memory; the cache is invalidated when any file's mtime
changes. The loader is thread-safe and safe to use from multiple agents.

Dependencies: standard library only (configparser, json, os, threading)
"""

from __future__ import annotations

import configparser
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .crypto_utils import decrypt_if_needed

log = logging.getLogger("sentinel.config_loader")

# ---------------------------------------------------------------------------
# Paths (resolved relative to this file's location at import time)
# ---------------------------------------------------------------------------

_THIS_DIR   = Path(__file__).resolve().parent          # bin/utils/
_BIN_DIR    = _THIS_DIR.parent                          # bin/
_APP_DIR    = _BIN_DIR.parent                           # sentinel/
_DEFAULT_DIR = _APP_DIR / "default"
_LOCAL_DIR   = _APP_DIR / "local"

# Environment variable prefix that overrides any config key.
# Format: SENTINEL_<SECTION>_<KEY> (both uppercased, dots → underscores)
_ENV_PREFIX = "SENTINEL_"

# ---------------------------------------------------------------------------
# Internal cache entry
# ---------------------------------------------------------------------------

class _CacheEntry:
    __slots__ = ("data", "mtimes")

    def __init__(self, data: Dict[str, Any], mtimes: Dict[str, float]) -> None:
        self.data   = data
        self.mtimes = mtimes   # path → mtime at load time

    def is_stale(self) -> bool:
        for path_str, recorded_mtime in self.mtimes.items():
            try:
                current = os.path.getmtime(path_str)
            except FileNotFoundError:
                current = 0.0
            if current != recorded_mtime:
                return True
        return False


# ---------------------------------------------------------------------------
# ConfigLoader
# ---------------------------------------------------------------------------

class ConfigLoader:
    """
    Hierarchical config loader for the SENTINEL app.

    Usage::

        cfg = ConfigLoader()
        host  = cfg.get("general", "splunk_host", default="localhost")
        port  = cfg.get_int("general", "splunk_port", default=8089)
        debug = cfg.get_bool("agents", "debug_mode", default=False)

    Environment variable override example::

        SENTINEL_GENERAL_SPLUNK_HOST=myhost python sentinel_orchestrator.py
    """

    def __init__(
        self,
        default_dir: Optional[Path] = None,
        local_dir: Optional[Path] = None,
    ) -> None:
        self._default_dir = Path(default_dir) if default_dir else _DEFAULT_DIR
        self._local_dir   = Path(local_dir)   if local_dir   else _LOCAL_DIR
        self._lock  = threading.RLock()
        # Keyed by filename stem (e.g. "sentinel" for sentinel.conf)
        self._cache: Dict[str, _CacheEntry] = {}

        log.debug(
            "ConfigLoader initialised",
            extra={
                "default_dir": str(self._default_dir),
                "local_dir":   str(self._local_dir),
            },
        )

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    def get(
        self,
        section: str,
        key: str,
        *,
        filename: str = "sentinel",
        default: Any = None,
        decrypt: bool = True,
    ) -> Optional[str]:
        """
        Return the string value for section/key, or ``default`` if absent.

        Lookup order:
          1. Environment variable  SENTINEL_<SECTION>_<KEY>  (uppercased)
          2. local/<filename>.conf or local/<filename>.json
          3. default/<filename>.conf or default/<filename>.json
        """
        # 1. Environment override
        env_key = f"{_ENV_PREFIX}{section.upper()}_{key.upper()}".replace(".", "_").replace("-", "_")
        env_val = os.environ.get(env_key)
        if env_val is not None:
            return decrypt_if_needed(env_val) if decrypt else env_val

        # 2 & 3. Merged config data
        data = self._load(filename)
        section_data = data.get(section.lower(), {})
        raw = section_data.get(key.lower())

        if raw is None:
            return default

        return (decrypt_if_needed(str(raw)) if decrypt else str(raw))

    def get_int(self, section: str, key: str, *,
                filename: str = "sentinel", default: int = 0) -> int:
        val = self.get(section, key, filename=filename, default=str(default))
        try:
            return int(str(val).strip())
        except (ValueError, TypeError):
            log.warning("Config %s/%s = %r is not an integer; using default %d",
                        section, key, val, default)
            return default

    def get_float(self, section: str, key: str, *,
                  filename: str = "sentinel", default: float = 0.0) -> float:
        val = self.get(section, key, filename=filename, default=str(default))
        try:
            return float(str(val).strip())
        except (ValueError, TypeError):
            log.warning("Config %s/%s = %r is not a float; using default %f",
                        section, key, val, default)
            return default

    def get_bool(self, section: str, key: str, *,
                 filename: str = "sentinel", default: bool = False) -> bool:
        val = self.get(section, key, filename=filename, default=None)
        if val is None:
            return default
        return str(val).strip().lower() in ("1", "true", "yes", "on", "enabled")

    def get_list(
        self,
        section: str,
        key: str,
        *,
        filename: str = "sentinel",
        delimiter: str = ",",
        default: Optional[List[str]] = None,
    ) -> List[str]:
        """Return a comma-split list; whitespace around each item is stripped."""
        val = self.get(section, key, filename=filename, default=None)
        if val is None:
            return default if default is not None else []
        return [item.strip() for item in val.split(delimiter) if item.strip()]

    def get_section(self, section: str, *,
                    filename: str = "sentinel") -> Dict[str, str]:
        """Return all key/value pairs in a section as a plain dict."""
        data = self._load(filename)
        return dict(data.get(section.lower(), {}))

    def reload(self, filename: str = "sentinel") -> None:
        """Force cache invalidation for a specific filename."""
        with self._lock:
            self._cache.pop(filename, None)
        log.debug("Config cache invalidated for '%s'", filename)

    def reload_all(self) -> None:
        """Force full cache flush."""
        with self._lock:
            self._cache.clear()
        log.debug("Full config cache cleared")

    # ------------------------------------------------------------------
    # Internal loading
    # ------------------------------------------------------------------

    def _load(self, filename: str) -> Dict[str, Dict[str, Any]]:
        """
        Return merged config for ``filename``, using cache when fresh.
        Thread-safe: acquires the RLock before reading or updating cache.
        """
        with self._lock:
            entry = self._cache.get(filename)
            if entry is not None and not entry.is_stale():
                return entry.data

            data, mtimes = self._read_and_merge(filename)
            self._cache[filename] = _CacheEntry(data, mtimes)
            return data

    def _read_and_merge(
        self, filename: str
    ) -> tuple[Dict[str, Dict[str, Any]], Dict[str, float]]:
        """
        Read default + local layers and merge them.
        Returns (merged_data, path_to_mtime_dict).
        """
        merged: Dict[str, Dict[str, Any]] = {}
        mtimes: Dict[str, float] = {}

        # Try .conf first, then .json for each layer
        for directory in (self._default_dir, self._local_dir):
            for suffix, reader in ((".conf", self._read_conf),
                                   (".json", self._read_json)):
                path = directory / f"{filename}{suffix}"
                if not path.exists():
                    mtimes[str(path)] = 0.0
                    continue
                try:
                    mtime = path.stat().st_mtime
                    mtimes[str(path)] = mtime
                    layer = reader(path)
                    _deep_merge(merged, layer)
                    log.debug("Loaded config layer %s", path)
                except Exception as exc:
                    log.error("Failed to load config %s: %s", path, exc)

        return merged, mtimes

    @staticmethod
    def _read_conf(path: Path) -> Dict[str, Dict[str, str]]:
        """
        Parse a Splunk-style .conf file (INI with no DEFAULT section).
        Splunk supports line continuation with backslash; configparser
        handles this natively.
        """
        parser = configparser.RawConfigParser(
            strict=False,
            inline_comment_prefixes=("#",),
        )
        # Don't lowercase keys — we do it ourselves for consistency.
        parser.optionxform = str  # type: ignore[assignment]
        parser.read(str(path), encoding="utf-8")

        result: Dict[str, Dict[str, str]] = {}
        for section in parser.sections():
            result[section.lower()] = {
                k.lower(): v
                for k, v in parser.items(section)
            }
        return result

    @staticmethod
    def _read_json(path: Path) -> Dict[str, Any]:
        """
        Parse a .json config file. Top-level keys become sections;
        nested dicts become key/value pairs. Non-dict top-level values
        are placed into a synthetic [global] section.
        """
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)

        if not isinstance(raw, dict):
            log.warning("JSON config %s is not a top-level object; skipping", path)
            return {}

        result: Dict[str, Any] = {}
        for k, v in raw.items():
            if isinstance(v, dict):
                result[k.lower()] = {
                    sk.lower(): sv for sk, sv in v.items()
                }
            else:
                result.setdefault("global", {})[k.lower()] = v
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _deep_merge(base: Dict, override: Dict) -> None:
    """Merge override into base in-place. Nested dicts are merged recursively."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


# ---------------------------------------------------------------------------
# Module-level singleton — agents import this directly
# ---------------------------------------------------------------------------

_default_loader: Optional[ConfigLoader] = None
_singleton_lock = threading.Lock()


def get_config(
    default_dir: Optional[Path] = None,
    local_dir: Optional[Path] = None,
) -> ConfigLoader:
    """
    Return the module-level ConfigLoader singleton.
    First call creates and caches it; subsequent calls return the same instance.
    Pass explicit directories only when testing.
    """
    global _default_loader
    with _singleton_lock:
        if _default_loader is None:
            _default_loader = ConfigLoader(default_dir, local_dir)
        return _default_loader


# ---------------------------------------------------------------------------
# __main__ — quick diagnostic dump
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    loader = ConfigLoader()

    sections_to_dump = [
        ("sentinel", "general"),
        ("sentinel", "agents"),
        ("sentinel", "hosted_models"),
        ("sentinel", "integrations"),
    ]

    print("\n=== SENTINEL Configuration Dump ===\n")
    for fname, section in sections_to_dump:
        data = loader.get_section(section, filename=fname)
        if data:
            print(f"[{section}]")
            for k, v in sorted(data.items()):
                # Redact encrypted values in the dump
                display = "***ENCRYPTED***" if v.startswith("$enc$") else v
                print(f"  {k} = {display}")
            print()

    # Show a few typed accessors
    print("get_int  general/splunk_port  →",
          loader.get_int("general", "splunk_port", default=8089))
    print("get_bool agents/debug_mode    →",
          loader.get_bool("agents", "debug_mode", default=False))
    print("get_list agents/enabled       →",
          loader.get_list("agents", "enabled",
                          default=["vanguard", "sherlock", "executor", "sage"]))
