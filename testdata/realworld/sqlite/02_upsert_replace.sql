-- Scenario: sync layer using SQLite conflict handling clauses
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS counters (
  name TEXT PRIMARY KEY,
  hits INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL COLLATE NOCASE UNIQUE
);
INSERT OR REPLACE INTO settings (key, value) VALUES ('theme', 'dark');
INSERT OR IGNORE INTO tags (name) VALUES ('work');
INSERT OR ABORT INTO tags (name) VALUES ('home');
INSERT OR FAIL INTO tags (name) VALUES ('misc');
INSERT OR ROLLBACK INTO tags (name) VALUES ('later');
REPLACE INTO settings (key, value) VALUES ('lang', 'en');
INSERT INTO counters (name, hits) VALUES ('home', 1) ON CONFLICT (name) DO UPDATE SET hits = hits + 1;
INSERT INTO counters (name, hits) VALUES ('home', 1) ON CONFLICT(name) DO UPDATE SET hits = counters.hits + excluded.hits;
INSERT INTO tags (name) VALUES ('x') ON CONFLICT DO NOTHING;
INSERT INTO tags (name) VALUES ('x') ON CONFLICT (name) DO NOTHING;
INSERT INTO settings (key, value) VALUES ('a', '1') ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = strftime('%s','now') WHERE settings.value <> excluded.value;
INSERT INTO counters (name, hits) VALUES ('x', 1) ON CONFLICT (name) DO UPDATE SET hits = hits + 1 RETURNING name, hits;
INSERT INTO counters (name, hits) SELECT name, 1 FROM tags WHERE true ON CONFLICT (name) DO UPDATE SET hits = hits + 1;
UPDATE OR IGNORE tags SET name = 'new' WHERE id = 3;
UPDATE OR REPLACE settings SET key = 'k2' WHERE key = 'k1';
INSERT INTO settings DEFAULT VALUES;
INSERT INTO settings (key, value) VALUES ('p', 'q') ON CONFLICT (key) WHERE value IS NOT NULL DO NOTHING;
INSERT INTO counters (name, hits) VALUES ('c', 1), ('d', 2) ON CONFLICT (name) DO UPDATE SET hits = excluded.hits RETURNING *;
