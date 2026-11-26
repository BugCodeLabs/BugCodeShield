ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_source_id_fkey;
ALTER TABLE scans
    ADD CONSTRAINT scans_source_id_fkey
    FOREIGN KEY (source_id) REFERENCES project_sources (id) ON DELETE CASCADE;
