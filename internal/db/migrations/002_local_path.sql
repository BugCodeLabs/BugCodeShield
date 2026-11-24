ALTER TABLE project_sources DROP CONSTRAINT IF EXISTS project_sources_kind_check;
ALTER TABLE project_sources ADD CONSTRAINT project_sources_kind_check
    CHECK (kind IN ('zip', 'files', 'github', 'local'));
ALTER TABLE project_sources ADD COLUMN IF NOT EXISTS local_path TEXT;
