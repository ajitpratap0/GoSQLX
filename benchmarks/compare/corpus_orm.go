package compare

// ORMQuery is one realistic ORM-style statement. Unlike Corpus, it is not
// restricted to the portable subset: it carries the quoting, placeholder and
// statement-shape habits of GORM, sqlx, ent and Rails-like layers, so a
// parser that only handles textbook SQL is exposed. Every parser receives the
// same text and rejections are reported, not hidden.
type ORMQuery struct {
	// ID is a stable identifier used in benchmark names and the results JSON.
	ID string
	// Name is a short human-readable label.
	Name string
	// Shape names the habit under test: quoted, placeholders, lowercase, ddl,
	// nesting or multistatement.
	Shape string
	// SQL is the text every parser receives.
	SQL string
}

// ORMCorpus is the ORM-style corpus, modelled on testdata/corpus/orm. Changing
// it invalidates published results for the orm_* queries.
var ORMCorpus = []ORMQuery{
	{
		ID: "orm_quoted_mysql", Name: "Backtick-quoted identifiers (GORM/MySQL)", Shape: "quoted",
		SQL: "SELECT `users`.`id`, `users`.`name`, `profiles`.`bio` FROM `users` LEFT JOIN `profiles` ON `profiles`.`user_id` = `users`.`id` " +
			"WHERE `users`.`deleted_at` IS NULL AND `users`.`age` > 21 ORDER BY `users`.`created_at` DESC LIMIT 20",
	},
	{
		ID: "orm_quoted_ansi", Name: "Double-quoted identifiers (GORM/PostgreSQL)", Shape: "quoted",
		SQL: `SELECT "users"."id", "users"."name", "profiles"."bio" FROM "users" LEFT JOIN "profiles" ON "profiles"."user_id" = "users"."id" ` +
			`WHERE "users"."deleted_at" IS NULL AND "users"."age" > 21 ORDER BY "users"."created_at" DESC LIMIT 20`,
	},
	{
		ID: "orm_placeholder_dollar", Name: "Numbered placeholders (sqlx/pgx)", Shape: "placeholders",
		SQL: "SELECT id, name, email FROM users WHERE active = $1 AND created_at > $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
	},
	{
		ID: "orm_placeholder_qmark", Name: "Question-mark placeholders (database/sql)", Shape: "placeholders",
		SQL: "SELECT id, name, email FROM users WHERE active = ? AND created_at > ? AND role IN (?, ?, ?) ORDER BY created_at DESC LIMIT ?",
	},
	{
		ID: "orm_placeholder_named", Name: "Named placeholders (sqlx)", Shape: "placeholders",
		SQL: "UPDATE users SET name = :name, email = :email, updated_at = :updated_at WHERE id = :id",
	},
	{
		ID: "orm_lowercase", Name: "Lowercase keywords (hand-written ORM output)", Shape: "lowercase",
		SQL: "select u.id, u.name, count(o.id) as order_count from users u inner join orders o on o.user_id = u.id " +
			"where u.active = true and o.total > 100 group by u.id, u.name having count(o.id) > 3 order by order_count desc limit 10",
	},
	{
		ID: "orm_insert_returning", Name: "INSERT ... RETURNING (ent/GORM/PostgreSQL)", Shape: "placeholders",
		SQL: `INSERT INTO "users" ("name", "email", "age", "created_at", "updated_at") VALUES ($1, $2, $3, $4, $5) RETURNING "id"`,
	},
	{
		ID: "orm_ddl_create", Name: "CREATE TABLE with constraints (auto-migrate)", Shape: "ddl",
		SQL: "CREATE TABLE users (id BIGINT NOT NULL, name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, age INT, " +
			"created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, deleted_at TIMESTAMP NULL, PRIMARY KEY (id), UNIQUE (email))",
	},
	{
		ID: "orm_ddl_index", Name: "CREATE INDEX (auto-migrate)", Shape: "ddl",
		SQL: "CREATE INDEX idx_users_deleted_at ON users (deleted_at)",
	},
	{
		ID: "orm_nesting", Name: "Deeply nested subqueries and CASE", Shape: "nesting",
		SQL: "SELECT id, name FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > (SELECT AVG(total) FROM orders WHERE status IN " +
			"(SELECT code FROM statuses WHERE kind = 'paid' AND region IN (SELECT region FROM regions WHERE active = 1)))) " +
			"AND CASE WHEN age > 65 THEN 1 WHEN age > 18 THEN 2 ELSE 3 END < 3",
	},
	{
		ID: "orm_multistatement", Name: "Two statements in one round trip (migration)", Shape: "multistatement",
		SQL: "UPDATE accounts SET balance = balance - 100 WHERE id = 1; UPDATE accounts SET balance = balance + 100 WHERE id = 2",
	},
}

// ORMQueryByID returns the ORM query with the given ID.
func ORMQueryByID(id string) (ORMQuery, bool) {
	for _, q := range ORMCorpus {
		if q.ID == id {
			return q, true
		}
	}
	return ORMQuery{}, false
}
