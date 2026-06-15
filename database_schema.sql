-- SENTINEL Live Data Stack — SQLite schema
-- Applied once at startup by start_live_stack.py / data_generators.init_db()

-- Raw events (ingested by generators, before parsing)
CREATE TABLE IF NOT EXISTS raw_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    index_name TEXT NOT NULL,
    sourcetype TEXT NOT NULL,
    _time REAL NOT NULL,
    host TEXT,
    source TEXT,
    raw_json TEXT NOT NULL,
    created_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Splunk-style events (parsed, queryable via the /api/search SPL-lite engine)
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    index_name TEXT NOT NULL,
    sourcetype TEXT NOT NULL,
    _time REAL NOT NULL,
    host TEXT,
    source TEXT,
    fields_json TEXT,
    raw_text TEXT
);

-- Alerts (notable events) — produced by the alert generator
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    host TEXT,
    user TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    process_name TEXT,
    command_line TEXT,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    status TEXT DEFAULT 'new',
    _time REAL NOT NULL,
    created_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Cases (SENTINEL processing pipeline)
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT UNIQUE NOT NULL,
    alert_id TEXT REFERENCES alerts(alert_id),
    status TEXT DEFAULT 'idle',
    vanguard_score REAL,
    vanguard_decision TEXT,
    sherlock_report_json TEXT,
    executor_actions_json TEXT,
    sage_analysis_json TEXT,
    created_at REAL DEFAULT (strftime('%s', 'now')),
    updated_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Agent state
CREATE TABLE IF NOT EXISTS agent_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_name TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'idle',
    current_case_id TEXT,
    last_action TEXT,
    last_action_time REAL,
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    queue_depth INTEGER DEFAULT 0
);

-- Response actions
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    execution_time_ms INTEGER,
    pre_state TEXT,
    post_state TEXT,
    rollback_timer INTEGER,
    created_at REAL DEFAULT (strftime('%s', 'now'))
);

-- Threat intel
CREATE TABLE IF NOT EXISTS threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    reputation_score REAL,
    threat_actor TEXT,
    malware_family TEXT,
    first_seen REAL,
    last_seen REAL,
    source TEXT
);

-- Performance metrics (time series)
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    _time REAL DEFAULT (strftime('%s', 'now'))
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_events_time   ON events(_time);
CREATE INDEX IF NOT EXISTS idx_events_index  ON events(index_name);
CREATE INDEX IF NOT EXISTS idx_alerts_time   ON alerts(_time);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_cases_status  ON cases(status);
CREATE INDEX IF NOT EXISTS idx_actions_case  ON actions(case_id);
CREATE INDEX IF NOT EXISTS idx_ti_ioc         ON threat_intel(ioc);
CREATE INDEX IF NOT EXISTS idx_metrics_name_time ON metrics(metric_name, _time);
