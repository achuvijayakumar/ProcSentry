ALTER TABLE processes ADD COLUMN systemd_unit VARCHAR(255);
ALTER TABLE processes ADD COLUMN ancestry_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE processes ADD COLUMN is_zombie BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE processes ADD COLUMN is_orphan BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE processes ADD COLUMN executable_deleted BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE processes ADD COLUMN executable_hash VARCHAR(128);
ALTER TABLE processes ADD COLUMN outbound_connections INTEGER NOT NULL DEFAULT 0;
ALTER TABLE processes ADD COLUMN restart_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE duplicate_groups ADD COLUMN explanations_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE alerts ADD COLUMN category VARCHAR(64) NOT NULL DEFAULT 'general';

CREATE INDEX IF NOT EXISTS ix_processes_systemd_unit ON processes(systemd_unit);
CREATE INDEX IF NOT EXISTS ix_processes_is_zombie ON processes(is_zombie);
CREATE INDEX IF NOT EXISTS ix_processes_is_orphan ON processes(is_orphan);
CREATE INDEX IF NOT EXISTS ix_processes_executable_deleted ON processes(executable_deleted);
CREATE INDEX IF NOT EXISTS ix_alerts_category ON alerts(category);

CREATE TABLE IF NOT EXISTS process_notes (
  id INTEGER PRIMARY KEY,
  pid INTEGER,
  fingerprint VARCHAR(128),
  tag VARCHAR(64),
  note TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_process_notes_pid ON process_notes(pid);
CREATE INDEX IF NOT EXISTS ix_process_notes_fingerprint ON process_notes(fingerprint);
CREATE INDEX IF NOT EXISTS ix_process_notes_tag ON process_notes(tag);
