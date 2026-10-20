-- Existing PostgreSQL databases only. Apply after a backup in a maintenance window.
-- Runtime persistence currently uses SQLite; its current NHI state migrates on open.
BEGIN;

ALTER TABLE lifecycle_events DROP CONSTRAINT IF EXISTS lifecycle_events_stage_check;
UPDATE lifecycle_events
SET detail = detail || jsonb_build_object('legacy_stage', stage),
    stage = CASE stage
        WHEN 'CREATION' THEN 'REGISTERED'
        WHEN 'PERMISSION_CHANGE' THEN 'ACTIVE'
        WHEN 'TERMINATION' THEN 'DEACTIVATED'
        WHEN 'DISPOSED' THEN 'DECOMMISSIONED'
        ELSE stage END
WHERE stage IN ('CREATION', 'PERMISSION_CHANGE', 'TERMINATION', 'DISPOSED');
ALTER TABLE lifecycle_events ADD CONSTRAINT lifecycle_events_stage_check
    CHECK (stage IN ('REGISTERED', 'ACTIVE', 'DEACTIVATED', 'DECOMMISSIONED'));

UPDATE nhi SET metadata = jsonb_set(metadata, '{lifecycle_stage}', to_jsonb(
    CASE metadata->>'lifecycle_stage'
        WHEN 'CREATION' THEN 'REGISTERED'
        WHEN 'PERMISSION_CHANGE' THEN 'ACTIVE'
        WHEN 'TERMINATION' THEN 'DEACTIVATED'
        WHEN 'DISPOSED' THEN 'DECOMMISSIONED'
        ELSE metadata->>'lifecycle_stage' END))
WHERE metadata->>'lifecycle_stage' IN ('CREATION', 'PERMISSION_CHANGE', 'TERMINATION', 'DISPOSED');

UPDATE change_requests SET
    before_state = CASE WHEN before_state ? 'lifecycle_stage' THEN
        jsonb_set(before_state, '{lifecycle_stage}', to_jsonb(CASE before_state->>'lifecycle_stage'
            WHEN 'CREATION' THEN 'REGISTERED' WHEN 'PERMISSION_CHANGE' THEN 'ACTIVE'
            WHEN 'TERMINATION' THEN 'DEACTIVATED' WHEN 'DISPOSED' THEN 'DECOMMISSIONED'
            ELSE before_state->>'lifecycle_stage' END)) ELSE before_state END,
    after_state = CASE WHEN after_state ? 'lifecycle_stage' THEN
        jsonb_set(after_state, '{lifecycle_stage}', to_jsonb(CASE after_state->>'lifecycle_stage'
            WHEN 'CREATION' THEN 'REGISTERED' WHEN 'PERMISSION_CHANGE' THEN 'ACTIVE'
            WHEN 'TERMINATION' THEN 'DEACTIVATED' WHEN 'DISPOSED' THEN 'DECOMMISSIONED'
            ELSE after_state->>'lifecycle_stage' END)) ELSE after_state END;

ALTER TABLE control_events DROP CONSTRAINT IF EXISTS control_events_verdict_check;
ALTER TABLE control_events ADD CONSTRAINT control_events_verdict_check
    CHECK (verdict IN ('ALLOW', 'ALERT', 'REVIEW', 'DENY', 'QUARANTINE'));
COMMIT;
