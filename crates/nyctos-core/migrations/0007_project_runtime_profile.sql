-- Project-level local build/run profile used by the future pentest
-- launcher. Stored as JSON in the project row for this first pass; the
-- typed API contract keeps it portable to a normalized launch profile
-- table later.
ALTER TABLE projects ADD COLUMN runtime_profile_json TEXT;
