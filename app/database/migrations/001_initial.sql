CREATE TABLE IF NOT EXISTS processes (
  id INTEGER PRIMARY KEY,
  pid INTEGER NOT NULL,
  ppid INTEGER,
  fingerprint VARCHAR(128),
  fuzzy_fingerprint VARCHAR(128),
  name VARCHAR(255) NOT NULL,
  cmdline TEXT NOT NULL,
  executable TEXT,
  cwd TEXT,
  cpu_percent FLOAT NOT NULL DEFAULT 0,
  memory_mb FLOAT NOT NULL DEFAULT 0,
  status VARCHAR(64),
  user VARCHAR(255),
  threads INTEGER NOT NULL DEFAULT 0,
  start_time DATETIME,
  ports_json TEXT NOT NULL DEFAULT '[]',
  service_manager VARCHAR(64),
  container_id VARCHAR(128),
  systemd_unit VARCHAR(255),
  ancestry_json TEXT NOT NULL DEFAULT '[]',
  is_zombie BOOLEAN NOT NULL DEFAULT 0,
  is_orphan BOOLEAN NOT NULL DEFAULT 0,
  executable_deleted BOOLEAN NOT NULL DEFAULT 0,
  executable_hash VARCHAR(128),
  outbound_connections INTEGER NOT NULL DEFAULT 0,
  duplicate_score INTEGER NOT NULL DEFAULT 0,
  suspicious_score INTEGER NOT NULL DEFAULT 0,
  restart_count INTEGER NOT NULL DEFAULT 0,
  first_seen_at DATETIME NOT NULL,
  last_seen_at DATETIME NOT NULL,
  CONSTRAINT uq_process_pid_start UNIQUE (pid, start_time)
);

CREATE TABLE IF NOT EXISTS process_history (
  id INTEGER PRIMARY KEY,
  process_id INTEGER NOT NULL REFERENCES processes(id) ON DELETE CASCADE,
  cpu_percent FLOAT NOT NULL,
  memory_mb FLOAT NOT NULL,
  thread_count INTEGER NOT NULL DEFAULT 0,
  timestamp DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS duplicate_groups (
  id INTEGER PRIMARY KEY,
  fingerprint VARCHAR(128) NOT NULL,
  confidence INTEGER NOT NULL,
  process_pids TEXT NOT NULL,
  reason TEXT NOT NULL,
  explanations_json TEXT NOT NULL DEFAULT '[]',
  detected_at DATETIME NOT NULL,
  resolved BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY,
  type VARCHAR(64) NOT NULL,
  severity VARCHAR(32) NOT NULL,
  category VARCHAR(64) NOT NULL DEFAULT 'general',
  message TEXT NOT NULL,
  pid INTEGER,
  fingerprint VARCHAR(128),
  created_at DATETIME NOT NULL,
  resolved BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS process_notes (
  id INTEGER PRIMARY KEY,
  pid INTEGER,
  fingerprint VARCHAR(128),
  tag VARCHAR(64),
  note TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL
);
