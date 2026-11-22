-- Scenario: ORM-style CRUD for a notes/todo mobile app
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  is_active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT,
  pinned INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO users (email, display_name) VALUES ('a@example.com', 'Alice');
INSERT INTO users (email, display_name) VALUES (?, ?);
INSERT INTO users (email, display_name) VALUES (:email, :name);
INSERT INTO notes (user_id, title, body) VALUES (1, 'Groceries', 'milk, eggs'), (1, 'Todo', 'ship it');
SELECT id, email, display_name FROM users WHERE id = ?;
SELECT * FROM notes WHERE user_id = ?1 ORDER BY pinned DESC, updated_at DESC LIMIT 20 OFFSET 40;
SELECT * FROM notes WHERE title LIKE '%' || ? || '%' ESCAPE '\' ORDER BY id;
SELECT count(*) FROM notes WHERE user_id = ? AND pinned = 1;
UPDATE notes SET title = ?, body = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?;
UPDATE users SET is_active = 0 WHERE id IN (SELECT user_id FROM notes GROUP BY user_id HAVING count(*) = 0);
DELETE FROM notes WHERE id = ? AND user_id = ?;
DELETE FROM notes WHERE updated_at < datetime('now', '-90 days');
INSERT INTO users (email, display_name) VALUES ('b@example.com', 'Bob') RETURNING id;
UPDATE notes SET pinned = 1 WHERE id = 5 RETURNING id, title, pinned;
DELETE FROM notes WHERE user_id = 9 RETURNING *;
SELECT n.id, n.title, u.display_name FROM notes AS n JOIN users AS u ON u.id = n.user_id WHERE u.is_active = 1;
SELECT n.id, u.email FROM notes n LEFT JOIN users u ON u.id = n.user_id WHERE u.id IS NULL;
SELECT EXISTS (SELECT 1 FROM users WHERE email = ?);
SELECT last_insert_rowid();
SELECT changes();
INSERT INTO notes (user_id, title) SELECT id, 'Welcome' FROM users WHERE id NOT IN (SELECT user_id FROM notes);
