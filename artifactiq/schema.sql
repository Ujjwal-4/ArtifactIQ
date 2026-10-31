-- ArtifactIQ v2 schema (SQLite). Managed by artifactiq.db: applied once, then
-- additive migration statements are tracked in the meta table.

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    case_number TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    investigator TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '',
    authorization TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT 'full',            -- full | targeted
    capability TEXT,                               -- targeted capability id
    status TEXT NOT NULL DEFAULT 'active',         -- active | archived
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,                     -- randomized; display-only name kept above
    data_path TEXT NOT NULL,                       -- relative to evidence store root
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,                          -- hash of the preserved copy
    source_hash TEXT,                              -- hash of original source, when a stable one was provided
    media_type TEXT NOT NULL,
    acquisition_method TEXT NOT NULL DEFAULT 'offline_upload',  -- offline_upload | live_collect | snapshot
    source_desc TEXT NOT NULL DEFAULT '',
    acquired_at TEXT NOT NULL,
    investigator TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    verify_status TEXT NOT NULL DEFAULT 'unverified', -- unverified | verified | mismatch | error
    verified_at TEXT,
    verified_hash TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);

CREATE TABLE IF NOT EXISTS custody_records (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    ts TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_records(evidence_id, seq);

CREATE TABLE IF NOT EXISTS parser_runs (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    parser TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    status TEXT NOT NULL,                          -- completed | completed_with_errors | failed | skipped | unsupported
    started_at TEXT NOT NULL,
    finished_at TEXT,
    events_added INTEGER NOT NULL DEFAULT 0,
    events_skipped INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    warnings INTEGER NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}'              -- JSON: per-record errors, coverage
);
CREATE INDEX IF NOT EXISTS idx_runs_case ON parser_runs(case_id);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ts_utc TEXT,                                   -- ISO-8601 UTC or NULL when unknown; never faked
    ts_original TEXT,
    ts_precision TEXT,                             -- utc | second | millisecond | local_unparsed | unknown
    ts_source TEXT,                                -- field path the timestamp was taken from
    event_type TEXT NOT NULL,
    category TEXT NOT NULL,
    channel TEXT,
    provider TEXT,
    event_code TEXT,                               -- provider event id / normalized code
    record_id TEXT,
    hostname TEXT,
    username TEXT,
    user_sid TEXT,
    process_name TEXT,
    process_id TEXT,
    parent_process_id TEXT,
    command_line TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    source_path TEXT,
    destination_path TEXT,
    raw_ref TEXT,                                  -- reference into the original artifact
    parser TEXT NOT NULL,
    parser_version TEXT,
    parse_status TEXT NOT NULL DEFAULT 'ok',       -- ok | partial | raw_only
    confidence REAL,
    tags TEXT NOT NULL DEFAULT '[]',
    dedupe_key TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_case_ts ON events(case_id, ts_utc);
CREATE INDEX IF NOT EXISTS idx_events_case_type ON events(case_id, event_type);
CREATE INDEX IF NOT EXISTS idx_events_case_evidence ON events(case_id, evidence_id);
CREATE INDEX IF NOT EXISTS idx_events_case_user ON events(case_id, username);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    rule_id TEXT,
    rule_version TEXT,
    severity INTEGER NOT NULL,                     -- 1..5 evidence-backed base severity
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    event_ids TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open',           -- open | confirmed | dismissed
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);

CREATE TABLE IF NOT EXISTS attack_mappings (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    finding_id TEXT,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    rationale TEXT NOT NULL,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    rule_version TEXT NOT NULL,
    confidence TEXT NOT NULL                       -- high | medium | low
);
CREATE INDEX IF NOT EXISTS idx_attack_case ON attack_mappings(case_id);

CREATE TABLE IF NOT EXISTS branches (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    question TEXT NOT NULL,
    why TEXT NOT NULL,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    event_ids TEXT NOT NULL DEFAULT '[]',
    missing_evidence TEXT NOT NULL DEFAULT '[]',
    steps TEXT NOT NULL DEFAULT '[]',
    priority INTEGER NOT NULL DEFAULT 0,
    priority_calc TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open',           -- open | confirmed | rejected | inconclusive | deferred
    closure_note TEXT NOT NULL DEFAULT '',
    rule_id TEXT,
    rule_version TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_branches_case ON branches(case_id);

CREATE TABLE IF NOT EXISTS simulations (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    scenario_id TEXT NOT NULL,                     -- SIM-C1..SIM-C5 knowledge-base entry
    title TEXT NOT NULL,
    trigger_rule TEXT NOT NULL,                    -- TR1..TR5 (what fired in this case)
    trigger_summary TEXT NOT NULL,
    trigger_event_ids TEXT NOT NULL DEFAULT '[]',
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    severity_base INTEGER NOT NULL DEFAULT 0,
    observed_count INTEGER NOT NULL DEFAULT 0,
    depth INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 0,
    priority_calc TEXT NOT NULL DEFAULT '{}',
    nodes TEXT NOT NULL DEFAULT '[]',              -- ordered chain; per-node status
    rule_version TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_simulations_case ON simulations(case_id);

CREATE TABLE IF NOT EXISTS risk_assessments (
    id TEXT PRIMARY KEY,
    case_id TEXT,
    version TEXT NOT NULL,                          -- scoring policy version
    score INTEGER NOT NULL,
    band TEXT NOT NULL,                             -- low | medium | high | critical
    inputs TEXT NOT NULL,                           -- JSON inputs with evidence backing
    formula TEXT NOT NULL,                          -- human readable formula
    computed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    etype TEXT NOT NULL,                            -- user | host | process | file | network | usb | service | task | evidence
    name TEXT NOT NULL,
    attrs TEXT NOT NULL DEFAULT '{}',
    key TEXT                                        -- dedupe key within case
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_entities_key ON entities(case_id, etype, key);

CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    src_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    dst_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    count INTEGER NOT NULL DEFAULT 1,
    last_ts TEXT
);
CREATE INDEX IF NOT EXISTS idx_rels_case ON relationships(case_id);

CREATE TABLE IF NOT EXISTS acquisition_sessions (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    operator TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'planned',        -- planned | running | completed | completed_with_warnings | failed | cancelled
    started_at TEXT,
    finished_at TEXT,
    plan TEXT NOT NULL DEFAULT '[]',               -- selected source ids
    authorization_ack INTEGER NOT NULL DEFAULT 0,
    impact_ack INTEGER NOT NULL DEFAULT 0,
    warnings TEXT NOT NULL DEFAULT '[]',
    log TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS acquisition_artifacts (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES acquisition_sessions(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_label TEXT NOT NULL,
    status TEXT NOT NULL,                          -- completed | completed_with_warnings | access_denied | unsupported | failed | skipped_with_reason
    message TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    evidence_id TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    warnings TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS phase_runs (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    phase TEXT NOT NULL,                           -- phase id (p1..p12 or capability id)
    status TEXT NOT NULL,                          -- not_started | ready | running | completed | completed_with_warnings | blocked | failed | skipped_with_reason
    started_at TEXT NOT NULL,
    finished_at TEXT,
    version TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_phase_runs_case ON phase_runs(case_id, phase);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    kind TEXT NOT NULL,                            -- html | json | csv_timeline | manifest | custody | pdf
    path TEXT NOT NULL,                            -- relative to reports dir
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    sha256 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS image_runs (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    status TEXT NOT NULL,                          -- completed | completed_with_warnings | failed
    engine TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    partitions TEXT NOT NULL DEFAULT '[]',         -- JSON partition summaries
    files INTEGER NOT NULL DEFAULT 0,
    dirs INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0,
    message TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_image_runs_case ON image_runs(case_id);

CREATE TABLE IF NOT EXISTS image_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES image_runs(id) ON DELETE CASCADE,
    case_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    path TEXT NOT NULL,
    is_dir INTEGER NOT NULL DEFAULT 0,
    deleted INTEGER NOT NULL DEFAULT 0,
    size INTEGER,
    crtime TEXT,                                   -- ISO-8601 UTC or NULL
    mtime TEXT,
    atime TEXT,
    ctime TEXT,
    inum TEXT
);
CREATE INDEX IF NOT EXISTS idx_image_files_run ON image_files(run_id);
CREATE INDEX IF NOT EXISTS idx_image_files_case ON image_files(case_id);
