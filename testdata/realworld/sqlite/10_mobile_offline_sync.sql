-- Scenario: mobile offline-first sync, outbox pattern and FTS
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  op TEXT NOT NULL CHECK (op IN ('insert', 'update', 'delete')),
  payload TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE (entity, entity_id, op)
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY NOT NULL,
  thread_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  body TEXT,
  sent_at INTEGER NOT NULL,
  read_at INTEGER,
  deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1))
);
CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages (thread_id, sent_at DESC) WHERE deleted = 0;
CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages (thread_id) WHERE read_at IS NULL AND deleted = 0;
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(body, content='messages', content_rowid='rowid');
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
  INSERT INTO messages_fts (rowid, body) VALUES (new.rowid, new.body);
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
  INSERT INTO messages_fts (messages_fts, rowid, body) VALUES ('delete', old.rowid, old.body);
END;
INSERT INTO outbox (entity, entity_id, op, payload) VALUES ('message', ?, 'insert', ?) ON CONFLICT (entity, entity_id, op) DO UPDATE SET payload = excluded.payload, attempts = 0;
SELECT * FROM outbox ORDER BY id LIMIT 50;
UPDATE outbox SET attempts = attempts + 1 WHERE id IN (?, ?, ?);
DELETE FROM outbox WHERE id <= ? AND attempts < 5;
SELECT thread_id, count(*) AS unread FROM messages WHERE read_at IS NULL AND deleted = 0 GROUP BY thread_id;
SELECT m.* FROM messages m WHERE m.thread_id = ? AND m.deleted = 0 AND m.sent_at < ? ORDER BY m.sent_at DESC LIMIT 30;
SELECT m.id, snippet(messages_fts, 0, '<b>', '</b>', '...', 8) FROM messages_fts JOIN messages m ON m.rowid = messages_fts.rowid WHERE messages_fts MATCH ? ORDER BY rank LIMIT 20;
SELECT * FROM messages_fts WHERE messages_fts MATCH 'hello AND world';
UPDATE messages SET read_at = unixepoch() WHERE thread_id = ? AND read_at IS NULL;
INSERT OR REPLACE INTO messages (id, thread_id, sender, body, sent_at) VALUES (?, ?, ?, ?, ?);
SELECT t.thread_id, t.last_at, m.body FROM (SELECT thread_id, max(sent_at) AS last_at FROM messages WHERE deleted = 0 GROUP BY thread_id) t JOIN messages m ON m.thread_id = t.thread_id AND m.sent_at = t.last_at ORDER BY t.last_at DESC;
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS sync_state (
  entity TEXT PRIMARY KEY,
  cursor TEXT,
  last_sync INTEGER
) STRICT;
