CREATE TABLE IF NOT EXISTS kill_records (
  id INTEGER PRIMARY KEY,
  pid INTEGER NOT NULL,
  name VARCHAR(255) NOT NULL,
  cmdline TEXT NOT NULL DEFAULT '',
  friendly_label VARCHAR(255),
  project VARCHAR(255),
  user VARCHAR(255),
  cpu_percent REAL NOT NULL DEFAULT 0,
  memory_mb REAL NOT NULL DEFAULT 0,
  killed_via VARCHAR(32) NOT NULL DEFAULT 'single',
  killed_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_kill_records_killed_at ON kill_records(killed_at);
CREATE INDEX IF NOT EXISTS ix_kill_records_name ON kill_records(name);
CREATE INDEX IF NOT EXISTS ix_kill_records_project ON kill_records(project);
