ALTER TABLE project_launch_profiles
    ADD COLUMN seed_steps_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE project_launch_profiles
    ADD COLUMN reset_steps_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE project_launch_profiles
    ADD COLUMN login_steps_json TEXT NOT NULL DEFAULT '[]';
