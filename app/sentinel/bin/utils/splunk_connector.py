"""
SENTINEL: Autonomous Agentic SOC Commander
splunk_connector.py — Splunk SDK connection manager

Wraps the splunklib Python SDK with:
  - Lazy connect with automatic reconnect on session expiry
  - Thread-safe connection reuse
  - Convenience methods for search, KV Store, notable events, and risk scores
  - SSL configuration from ConfigLoader
  - Timeout and result-size guards

Dependencies: splunk-sdk (splunklib) in requirements.txt, standard library
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Generator, Iterator, List, Optional

log = logging.getLogger("sentinel.splunk_connector")

# splunklib is bundled with Splunk Enterprise under $SPLUNK_HOME/lib/python3.x/
# and also installable via pip (splunk-sdk). Import gracefully so the module
# is importable during unit tests that mock it out.
try:
    import splunklib.client as splunk_client
    import splunklib.results as splunk_results
    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False
    log.warning(
        "splunklib not found. Install splunk-sdk or run inside Splunk. "
        "All SplunkConnector operations will raise RuntimeError."
    )


# ---------------------------------------------------------------------------
# SplunkConnector
# ---------------------------------------------------------------------------

class SplunkConnector:
    """
    Thread-safe Splunk REST API wrapper.

    Configuration is read from ConfigLoader on first connect; override via
    constructor kwargs for testing.

    Example::

        conn = SplunkConnector()
        results = conn.search("index=endpoint | head 10")
        for row in results:
            print(row)
    """

    # How long a successful connection is considered valid before re-auth.
    _SESSION_TTL_SECONDS = 3600

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        app: str = "sentinel",
        owner: str = "nobody",
        scheme: str = "https",
        verify_ssl: bool = False,
        search_timeout: int = 120,
        max_results: int = 10_000,
    ) -> None:
        # If not provided, values are loaded lazily from ConfigLoader on first _connect()
        self._host_override     = host
        self._port_override     = port
        self._username_override = username
        self._password_override = password
        self._token_override    = token
        self._app               = app
        self._owner             = owner
        self._scheme            = scheme
        self._verify_ssl        = verify_ssl
        self._search_timeout    = search_timeout
        self._max_results       = max_results

        self._service: Optional["splunk_client.Service"] = None
        self._connected_at: float = 0.0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> "splunk_client.Service":
        """
        Open (or reuse) a Splunk REST API session.
        Re-authenticates automatically if the session TTL has expired.
        Thread-safe: only one thread performs the auth at a time.
        """
        with self._lock:
            if self._service is not None:
                if time.time() - self._connected_at < self._SESSION_TTL_SECONDS:
                    return self._service
                log.info("Splunk session TTL expired; reconnecting")

            self._service = self._connect()
            self._connected_at = time.time()
            return self._service

    def _connect(self) -> "splunk_client.Service":
        if not _SDK_AVAILABLE:
            raise RuntimeError(
                "splunklib is not installed. Cannot connect to Splunk."
            )

        # Resolve connection parameters: constructor > ConfigLoader > defaults
        from .config_loader import get_config
        cfg = get_config()

        host   = self._host_override   or cfg.get("general", "splunk_host",   default="localhost")
        port   = self._port_override   or cfg.get_int("general", "splunk_port", default=8089)
        scheme = self._scheme          or cfg.get("general", "splunk_scheme", default="https")

        # Prefer token auth; fall back to username/password
        token    = self._token_override    or cfg.get("splunk",  "api_token",  default="")
        username = self._username_override or cfg.get("splunk",  "username",   default="admin")
        password = self._password_override or cfg.get("splunk",  "password",   default="")

        kwargs: Dict[str, Any] = {
            "host":            host,
            "port":            int(port),
            "scheme":          scheme,
            "app":             self._app,
            "owner":           self._owner,
            "autologin":       True,
            "verify":          self._verify_ssl,
        }

        if token:
            kwargs["splunkToken"] = token
        elif username and password:
            kwargs["username"] = username
            kwargs["password"] = password
        else:
            raise RuntimeError(
                "No Splunk credentials available. Set SENTINEL_SPLUNK_API_TOKEN "
                "or configure [splunk] username/password in sentinel.local.conf."
            )

        log.info(
            "Connecting to Splunk",
            extra={"host": host, "port": port, "scheme": scheme, "app": self._app},
        )
        service = splunk_client.connect(**kwargs)
        log.info("Splunk connection established", extra={"host": host})
        return service

    def disconnect(self) -> None:
        with self._lock:
            if self._service:
                try:
                    self._service.logout()
                except Exception:
                    pass
                self._service = None
                log.info("Splunk connection closed")

    def is_connected(self) -> bool:
        with self._lock:
            return (
                self._service is not None
                and (time.time() - self._connected_at) < self._SESSION_TTL_SECONDS
            )

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(
        self,
        spl: str,
        earliest: str = "-24h",
        latest: str = "now",
        max_results: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute a blocking SPL search and return all results as a list of dicts.

        For very large result sets, use search_iter() which yields results
        page by page to avoid loading everything into memory.
        """
        service = self.connect()
        limit   = min(max_results or self._max_results, self._max_results)
        t_out   = timeout or self._search_timeout

        kwargs = {
            "exec_mode":   "blocking",
            "earliest_time": earliest,
            "latest_time":   latest,
            "output_mode":   "json",
            "count":         limit,
            "timeout":       t_out,
        }

        log.debug("Executing SPL search",
                  extra={"spl_preview": spl[:200], "earliest": earliest, "latest": latest})

        try:
            job = service.jobs.create(spl, **kwargs)
            reader = splunk_results.JSONResultsReader(job.results(output_mode="json", count=limit))
            rows: List[Dict[str, Any]] = []
            for item in reader:
                if isinstance(item, splunk_results.Message):
                    log.debug("Splunk search message: [%s] %s", item.type, item.message)
                elif isinstance(item, dict):
                    rows.append(item)
            return rows
        except Exception as exc:
            log.error("Splunk search failed: %s", exc,
                      extra={"spl_preview": spl[:200]})
            # Invalidate session so next call triggers reconnect
            with self._lock:
                self._service = None
            raise

    def search_iter(
        self,
        spl: str,
        earliest: str = "-24h",
        latest: str = "now",
        page_size: int = 1000,
        timeout: Optional[int] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Execute a SPL search and yield results row by row.
        Suitable for large result sets that should not be fully buffered.
        """
        service = self.connect()
        t_out   = timeout or self._search_timeout

        job = service.jobs.create(
            spl,
            exec_mode="normal",
            earliest_time=earliest,
            latest_time=latest,
            output_mode="json",
            timeout=t_out,
        )

        # Poll until done
        while not job.is_done():
            time.sleep(0.5)

        offset = 0
        while True:
            reader = splunk_results.JSONResultsReader(
                job.results(output_mode="json", count=page_size, offset=offset)
            )
            batch: List[Dict[str, Any]] = []
            for item in reader:
                if isinstance(item, dict):
                    batch.append(item)
            if not batch:
                break
            for row in batch:
                yield row
            offset += len(batch)

        job.cancel()

    def search_one(
        self,
        spl: str,
        earliest: str = "-24h",
        latest: str = "now",
    ) -> Optional[Dict[str, Any]]:
        """Return the first result or None."""
        results = self.search(spl, earliest=earliest, latest=latest, max_results=1)
        return results[0] if results else None

    # ------------------------------------------------------------------
    # Saved searches
    # ------------------------------------------------------------------

    def get_saved_searches(
        self, app: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Return metadata for all saved searches in the given app namespace."""
        service = self.connect()
        ns_app = app or self._app
        searches = service.saved_searches
        result = []
        for ss in searches:
            if ss.access.app == ns_app or ns_app == "*":
                result.append({
                    "name":        ss.name,
                    "search":      ss["search"],
                    "description": ss.get("description", ""),
                    "app":         ss.access.app,
                    "disabled":    ss.get("disabled", "0"),
                })
        return result

    def dispatch_saved_search(
        self,
        name: str,
        earliest: str = "",
        latest: str = "",
        dispatch_args: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Dispatch a saved search by name and return its results."""
        service = self.connect()
        ss = service.saved_searches[name]
        kwargs: Dict[str, Any] = dispatch_args or {}
        if earliest:
            kwargs["dispatch.earliest_time"] = earliest
        if latest:
            kwargs["dispatch.latest_time"] = latest

        job = ss.dispatch(**kwargs)
        while not job.is_done():
            time.sleep(0.5)

        reader = splunk_results.JSONResultsReader(
            job.results(output_mode="json", count=self._max_results)
        )
        rows = [item for item in reader if isinstance(item, dict)]
        job.cancel()
        return rows

    # ------------------------------------------------------------------
    # KV Store
    # ------------------------------------------------------------------

    def kvstore_get(
        self,
        collection: str,
        key: str,
        app: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a single KV Store record by _key."""
        service = self.connect()
        ns_app = app or self._app
        try:
            coll = service.kvstore[collection]
            return coll.data.query_by_id(key)
        except Exception as exc:
            log.debug("KV Store get miss: %s/%s — %s", collection, key, exc)
            return None

    def kvstore_query(
        self,
        collection: str,
        query: Optional[Dict[str, Any]] = None,
        sort: Optional[str] = None,
        limit: int = 0,
        app: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query a KV Store collection with an optional MongoDB-style filter."""
        service = self.connect()
        ns_app = app or self._app
        coll = service.kvstore[collection]

        kwargs: Dict[str, Any] = {}
        if query:
            import json as _json
            kwargs["query"] = _json.dumps(query)
        if sort:
            kwargs["sort"] = sort
        if limit:
            kwargs["limit"] = limit

        return list(coll.data.query(**kwargs))

    def kvstore_upsert(
        self,
        collection: str,
        key: str,
        record: Dict[str, Any],
        app: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Insert or update a KV Store record.
        If ``key`` already exists the record is replaced; otherwise inserted.
        Returns the stored record.
        """
        service = self.connect()
        coll = service.kvstore[collection]
        record["_key"] = key

        existing = self.kvstore_get(collection, key, app=app)
        if existing is not None:
            coll.data.update(key, record)
        else:
            coll.data.insert(record)
        return record

    def kvstore_delete(
        self,
        collection: str,
        key: str,
        app: Optional[str] = None,
    ) -> bool:
        """Delete a KV Store record by _key. Returns True if deleted."""
        service = self.connect()
        coll = service.kvstore[collection]
        try:
            coll.data.delete_by_id(key)
            return True
        except Exception as exc:
            log.warning("KV Store delete failed for %s/%s: %s", collection, key, exc)
            return False

    def kvstore_batch_delete(
        self,
        collection: str,
        query: Dict[str, Any],
        app: Optional[str] = None,
    ) -> int:
        """Delete all records matching query. Returns count of deleted records."""
        service = self.connect()
        import json as _json
        coll = service.kvstore[collection]
        # Fetch matching keys first, then delete
        matches = list(coll.data.query(query=_json.dumps(query)))
        for rec in matches:
            coll.data.delete_by_id(rec["_key"])
        return len(matches)

    # ------------------------------------------------------------------
    # Enterprise Security — Notable Events
    # ------------------------------------------------------------------

    def create_notable(
        self,
        rule_name: str,
        severity: str,
        host: str,
        user: str,
        description: str,
        risk_score: int = 50,
        fields: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Create a new ES notable event by writing directly to the notable index.
        Returns the event ID of the created notable.
        """
        import uuid as _uuid

        event_id = f"SEN-NOTABLE-{_uuid.uuid4().hex[:12].upper()}"
        record = {
            "event_id":    event_id,
            "rule_name":   rule_name,
            "severity":    severity,
            "dest":        host,
            "user":        user,
            "description": description,
            "risk_score":  risk_score,
            "status":      "new",
            "owner":       "SENTINEL",
            "source":      "SENTINEL Autonomous SOC",
            **(fields or {}),
        }

        spl = (
            f"| makeresults | eval "
            + ", ".join(f'{k}="{v}"' for k, v in record.items())
            + ' | collect index=notable source="SENTINEL" sourcetype="stash"'
        )
        try:
            self.search(spl, earliest="rt", latest="rt")
            log.info("Created notable event", extra={"event_id": event_id})
            return event_id
        except Exception as exc:
            log.error("Failed to create notable event: %s", exc)
            return None

    def update_risk_score(
        self,
        host: Optional[str] = None,
        user: Optional[str] = None,
        risk_score: int = 0,
        rule_name: str = "SENTINEL Risk Update",
        threat_object_type: str = "system",
    ) -> bool:
        """
        Adjust the ES Risk Score for a host or user via the risk index.
        At least one of host or user must be provided.
        """
        if not host and not user:
            raise ValueError("Either host or user must be specified.")

        threat_object = host or user
        spl = (
            f'| makeresults | eval '
            f'risk_object="{threat_object}", '
            f'risk_object_type="{threat_object_type}", '
            f'risk_score={risk_score}, '
            f'rule_name="{rule_name}", '
            f'source="SENTINEL" '
            f'| collect index=risk sourcetype="stash"'
        )
        try:
            self.search(spl, earliest="rt", latest="rt")
            return True
        except Exception as exc:
            log.error("Failed to update risk score: %s", exc)
            return False

    def get_risk_score(
        self,
        risk_object: str,
        lookback: str = "-24h",
    ) -> int:
        """Return the current cumulative risk score for a host or user."""
        spl = (
            f'index=risk risk_object="{risk_object}" '
            f'| stats sum(risk_score) AS total_risk'
        )
        row = self.search_one(spl, earliest=lookback, latest="now")
        if row:
            try:
                return int(float(row.get("total_risk", 0)))
            except (ValueError, TypeError):
                pass
        return 0

    # ------------------------------------------------------------------
    # Indexes
    # ------------------------------------------------------------------

    def list_indexes(self, filter: str = "") -> List[str]:
        """Return names of accessible indexes, optionally filtered."""
        service = self.connect()
        names = [idx.name for idx in service.indexes]
        if filter:
            names = [n for n in names if filter.lower() in n.lower()]
        return sorted(names)

    def index_exists(self, name: str) -> bool:
        return name in self.list_indexes()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_singleton: Optional[SplunkConnector] = None
_singleton_lock = threading.Lock()


def get_connector(**kwargs: Any) -> SplunkConnector:
    """
    Return the module-level SplunkConnector singleton.
    Pass kwargs only on the first call to customise the connection parameters.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SplunkConnector(**kwargs)
        return _singleton
