-- Legacy SQLite decision tables (retired 2026-10-10; decisions live in the solo-decisions cell).
-- Tests apply this DDL to a temporary database for SqliteDecisionStore; production never does.

CREATE TABLE IF NOT EXISTS decision_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    domain TEXT NOT NULL DEFAULT 'general',
    decision TEXT NOT NULL,
    rationale TEXT,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    confidence REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    expected_outcome TEXT,
    actual_outcome TEXT,
    next_action TEXT,
    status TEXT NOT NULL DEFAULT 'proposed'
        CHECK (status IN ('draft', 'proposed', 'approved', 'in_progress', 'completed', 'deferred', 'rejected', 'superseded')),
    approval_required INTEGER NOT NULL DEFAULT 1 CHECK (approval_required IN (0, 1)),
    approval_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (approval_status IN ('pending', 'approved', 'rejected', 'not_required')),
    action_type TEXT NOT NULL DEFAULT 'none'
        CHECK (action_type IN ('none', 'task', 'calendar', 'notification', 'message', 'financial', 'external_change')),
    action_status TEXT NOT NULL DEFAULT 'none'
        CHECK (action_status IN ('none', 'pending_approval', 'queued', 'executed', 'blocked', 'failed')),
    privacy_class TEXT NOT NULL DEFAULT 'private'
        CHECK (privacy_class IN ('private', 'sensitive', 'internal')),
    source_type TEXT,
    source_ref TEXT,
    review_date DATE,
    decided_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    dedupe_key TEXT,
    execution_lock_key TEXT
);

CREATE TABLE IF NOT EXISTS decision_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id INTEGER NOT NULL REFERENCES decision_records(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL
        CHECK (event_type IN ('created', 'refreshed', 'approved', 'rejected', 'deferred', 'completed', 'signal_cleared', 'review_task_created', 'reviewed', 'updated')),
    actor TEXT NOT NULL DEFAULT 'system',
    from_status TEXT,
    to_status TEXT,
    from_approval_status TEXT,
    to_approval_status TEXT,
    from_action_status TEXT,
    to_action_status TEXT,
    reason TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS decision_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id INTEGER NOT NULL REFERENCES decision_records(id) ON DELETE CASCADE,
    task_id INTEGER,
    due_date DATE NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'completed', 'skipped')),
    reviewer TEXT,
    outcome TEXT,
    notes TEXT,
    reviewed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(decision_id, due_date)
);

CREATE INDEX IF NOT EXISTS idx_decision_records_status
    ON decision_records(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_decision_records_approval
    ON decision_records(approval_status, approval_required);

CREATE INDEX IF NOT EXISTS idx_decision_records_review
    ON decision_records(review_date);

CREATE INDEX IF NOT EXISTS idx_decision_records_domain
    ON decision_records(domain, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_decision_records_dedupe
    ON decision_records(dedupe_key)
    WHERE dedupe_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_decision_records_execution_lock
    ON decision_records(execution_lock_key)
    WHERE execution_lock_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_decision_events_decision
    ON decision_events(decision_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_decision_events_type
    ON decision_events(event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_decision_reviews_decision
    ON decision_reviews(decision_id, due_date DESC);

CREATE INDEX IF NOT EXISTS idx_decision_reviews_due
    ON decision_reviews(status, due_date);
