-- Stable manifest identity for built-in teams; existing teams remain user-owned.
ALTER TABLE teams ADD COLUMN source TEXT NOT NULL DEFAULT 'user';
ALTER TABLE teams ADD COLUMN source_ref TEXT;

-- A manifest is materialized independently for each user, including archived rows.
CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_builtin_source_ref
    ON teams(user_id, source_ref)
    WHERE source = 'builtin' AND source_ref IS NOT NULL;
