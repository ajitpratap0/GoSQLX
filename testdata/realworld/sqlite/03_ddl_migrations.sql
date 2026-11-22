-- Scenario: schema migrations for an Electron app
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  balance REAL NOT NULL DEFAULT 0.0 CHECK (balance >= 0),
  currency TEXT NOT NULL DEFAULT 'USD' CHECK (length(currency) = 3),
  meta BLOB
);
CREATE TABLE transactions (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL,
  amount NUMERIC NOT NULL,
  memo TEXT,
  posted_at TEXT NOT NULL,
  FOREIGN KEY (account_id) REFERENCES accounts (id) ON UPDATE CASCADE ON DELETE RESTRICT
);
CREATE TABLE strict_events (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  payload TEXT,
  ts INTEGER NOT NULL
) STRICT;
CREATE TABLE strict_wr (
  k TEXT PRIMARY KEY,
  v ANY
) STRICT, WITHOUT ROWID;
CREATE TABLE typeless (a, b, c);
CREATE TABLE gen (
  a INTEGER,
  b INTEGER,
  c INTEGER GENERATED ALWAYS AS (a + b) VIRTUAL,
  d INTEGER AS (a * b) STORED
);
CREATE TEMP TABLE scratch (id INTEGER, v TEXT);
CREATE TEMPORARY TABLE IF NOT EXISTS scratch2 (id INTEGER);
CREATE TABLE copy_of_accounts AS SELECT * FROM accounts WHERE balance > 0;
CREATE INDEX IF NOT EXISTS idx_tx_account ON transactions (account_id, posted_at DESC);
CREATE UNIQUE INDEX uq_accounts_name ON accounts (name COLLATE NOCASE);
CREATE INDEX idx_tx_big ON transactions (amount) WHERE amount > 1000;
CREATE INDEX idx_tx_month ON transactions (strftime('%Y-%m', posted_at));
CREATE VIEW IF NOT EXISTS v_account_totals AS
  SELECT a.id, a.name, coalesce(sum(t.amount), 0) AS total FROM accounts a LEFT JOIN transactions t ON t.account_id = a.id GROUP BY a.id, a.name;
CREATE TEMP VIEW v_tmp AS SELECT 1 AS one;
ALTER TABLE accounts ADD COLUMN archived INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts RENAME COLUMN name TO title;
ALTER TABLE accounts RENAME TO accounts_old;
ALTER TABLE transactions DROP COLUMN memo;
DROP TABLE IF EXISTS scratch;
DROP INDEX IF EXISTS idx_tx_big;
DROP VIEW IF EXISTS v_tmp;
CREATE TRIGGER trg_tx_after_insert AFTER INSERT ON transactions
BEGIN
  UPDATE accounts SET balance = balance + NEW.amount WHERE id = NEW.account_id;
END;
CREATE TRIGGER IF NOT EXISTS trg_notes_touch BEFORE UPDATE OF title, body ON notes FOR EACH ROW WHEN NEW.title <> OLD.title
BEGIN
  UPDATE notes SET updated_at = datetime('now') WHERE id = NEW.id;
END;
DROP TRIGGER IF EXISTS trg_notes_touch;
CREATE VIRTUAL TABLE docs_fts USING fts5(title, body);
BEGIN;
BEGIN IMMEDIATE;
COMMIT;
BEGIN TRANSACTION;
ROLLBACK;
SAVEPOINT sp1;
RELEASE SAVEPOINT sp1;
REINDEX idx_tx_account;
ANALYZE;
VACUUM;
