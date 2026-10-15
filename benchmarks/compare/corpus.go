// Package compare is a reproducible benchmark harness that measures GoSQLX
// against other Go SQL parsers on an identical query corpus (issue #673).
//
// It lives in its own Go module so competitor dependencies (including the
// CGo-based pg_query_go) never leak into the GoSQLX module. Every competitor
// version is pinned in this module's go.mod; GoSQLX itself is resolved from
// the enclosing repository through a replace directive, so the harness always
// measures the checked-out commit.
//
// Every benchmark measures the end-to-end stage: SQL text in, AST out. The
// libraries parse different dialects and produce different ASTs, so the
// numbers compare the cost of getting a usable tree, not identical work.
package compare

// Query is one entry in the shared corpus. Every parser receives exactly the
// same SQL text.
type Query struct {
	// ID is a stable identifier used in benchmark names and the results JSON.
	ID string
	// Name is a short human-readable label.
	Name string
	// SQL is the statement text. It sticks to a portable subset (no quoted
	// identifiers, no dialect-specific operators) so that a MySQL-family
	// grammar and the PostgreSQL grammar can both accept it.
	SQL string
}

// Corpus is the shared, ordered query corpus. Changing it invalidates
// previously published results, so regenerate results/latest.json afterwards.
var Corpus = []Query{
	{
		ID:   "simple_select",
		Name: "Simple SELECT",
		SQL:  "SELECT id, name FROM users",
	},
	{
		ID:   "select_where",
		Name: "SELECT with WHERE, ORDER BY, LIMIT",
		SQL:  "SELECT id, name, email FROM users WHERE active = 1 AND created_at > '2024-01-01' ORDER BY name LIMIT 10",
	},
	{
		ID:   "join",
		Name: "Two-table JOIN",
		SQL:  "SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 100 ORDER BY o.total DESC LIMIT 50",
	},
	{
		ID:   "aggregate",
		Name: "GROUP BY with HAVING",
		SQL:  "SELECT status, COUNT(*), SUM(total) FROM orders GROUP BY status HAVING COUNT(*) > 10",
	},
	{
		ID:   "subquery",
		Name: "IN subquery",
		SQL:  "SELECT name FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 1000)",
	},
	{
		ID:   "cte",
		Name: "Common table expression",
		SQL:  "WITH recent AS (SELECT user_id, total FROM orders WHERE total > 100) SELECT user_id, SUM(total) FROM recent GROUP BY user_id",
	},
	{
		ID:   "window",
		Name: "Window function",
		SQL:  "SELECT name, salary, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) FROM employees",
	},
	{
		ID:   "complex",
		Name: "Multi-JOIN analytical query",
		SQL: "SELECT c.name, p.category, COUNT(o.id), SUM(oi.quantity * oi.price) " +
			"FROM customers c " +
			"JOIN orders o ON c.id = o.customer_id " +
			"JOIN order_items oi ON o.id = oi.order_id " +
			"LEFT JOIN products p ON oi.product_id = p.id " +
			"WHERE o.created_at >= '2024-01-01' AND p.category IS NOT NULL " +
			"GROUP BY c.name, p.category " +
			"HAVING SUM(oi.quantity * oi.price) > 500 " +
			"ORDER BY c.name, p.category LIMIT 100",
	},
	{
		ID:   "insert",
		Name: "INSERT VALUES",
		SQL:  "INSERT INTO users (id, name, email) VALUES (1, 'alice', 'alice@example.com')",
	},
	{
		ID:   "update",
		Name: "UPDATE with WHERE",
		SQL:  "UPDATE users SET name = 'bob', active = 0 WHERE id = 42",
	},
	{
		ID:   "delete",
		Name: "DELETE with WHERE",
		SQL:  "DELETE FROM sessions WHERE expires_at < '2024-01-01'",
	},
}
