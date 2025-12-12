// Package ast provides Abstract Syntax Tree (AST) node definitions for SQL statements.
//
// This package implements a comprehensive AST representation for SQL with support for
// multiple SQL dialects (PostgreSQL, MySQL, SQL Server, Oracle, SQLite). It includes
// extensive object pooling for memory efficiency and high-performance SQL parsing.
//
// # Architecture Overview
//
// The AST package follows a hierarchical node structure with three primary interfaces:
//
//   - Node: Base interface for all AST nodes (TokenLiteral, Children methods)
//   - Statement: Interface for SQL statements (SELECT, INSERT, UPDATE, DELETE, etc.)
//   - Expression: Interface for SQL expressions (binary ops, functions, literals, etc.)
//
// All AST nodes implement the Node interface, providing a uniform way to traverse and
// inspect the syntax tree using the visitor pattern.
//
// # Node Interface Hierarchy
//
//	Node (base interface)
//	├── Statement (SQL statements)
//	│   ├── SelectStatement
//	│   ├── InsertStatement
//	│   ├── UpdateStatement
//	│   ├── DeleteStatement
//	│   ├── CreateTableStatement
//	│   ├── MergeStatement
//	│   ├── TruncateStatement
//	│   ├── DropStatement
//	│   ├── CreateViewStatement
//	│   ├── CreateMaterializedViewStatement
//	│   ├── WithClause (CTEs)
//	│   └── SetOperation (UNION, EXCEPT, INTERSECT)
//	└── Expression (SQL expressions)
//	    ├── Identifier
//	    ├── LiteralValue
//	    ├── BinaryExpression
//	    ├── UnaryExpression
//	    ├── FunctionCall
//	    ├── CaseExpression
//	    ├── BetweenExpression
//	    ├── InExpression
//	    ├── ExistsExpression
//	    ├── SubqueryExpression
//	    ├── CastExpression
//	    └── AliasedExpression
//
// # Object Pooling for Performance
//
// The ast package provides extensive object pooling to minimize memory allocations
// and improve performance in high-throughput scenarios. Object pools are available
// for all major AST node types.
//
// Pool Usage Pattern (MANDATORY for optimal performance):
//
//	// Get AST from pool
//	astObj := ast.NewAST()
//	defer ast.ReleaseAST(astObj)  // ALWAYS use defer to prevent leaks
//
//	// Get statements from pools
//	stmt := ast.GetSelectStatement()
//	defer ast.PutSelectStatement(stmt)
//
//	// Get expressions from pools
//	expr := ast.GetBinaryExpression()
//	defer ast.PutBinaryExpression(expr)
//
//	// Use pooled objects
//	// ... build and use AST nodes ...
//
// Available Pools:
//
//   - AST Pool: NewAST() / ReleaseAST()
//   - Statement Pools: GetSelectStatement(), GetInsertStatement(), GetUpdateStatement(), GetDeleteStatement()
//   - Expression Pools: GetIdentifier(), GetBinaryExpression(), GetLiteralValue(), GetFunctionCall(), etc.
//   - Slice Pools: GetExpressionSlice() / PutExpressionSlice()
//
// Performance Impact: Object pooling provides 60-80% memory reduction and significantly
// reduces GC pressure in production workloads with 95%+ pool hit rates.
//
// # Visitor Pattern for Tree Traversal
//
// The package provides a visitor pattern implementation for traversing and inspecting
// AST nodes. The visitor pattern is defined in visitor.go and provides two interfaces:
//
//   - Visitor: Standard visitor interface with Visit(Node) method
//   - Inspector: Simplified function-based visitor
//
// Example - Walking the AST tree:
//
//	// Using the Visitor interface
//	type MyVisitor struct {
//	    depth int
//	}
//
//	func (v *MyVisitor) Visit(node ast.Node) (ast.Visitor, error) {
//	    if node == nil {
//	        return nil, nil
//	    }
//	    fmt.Printf("Visiting: %s at depth %d\n", node.TokenLiteral(), v.depth)
//	    return &MyVisitor{depth: v.depth + 1}, nil
//	}
//
//	visitor := &MyVisitor{depth: 0}
//	ast.Walk(visitor, astNode)
//
// Example - Using Inspector for simplified traversal:
//
//	// Count all SELECT statements in the AST
//	selectCount := 0
//	ast.Inspect(astNode, func(n ast.Node) bool {
//	    if _, ok := n.(*ast.SelectStatement); ok {
//	        selectCount++
//	    }
//	    return true // Continue traversal
//	})
//
// Example - Finding specific node types:
//
//	// Find all binary expressions with AND operator
//	var andExprs []*ast.BinaryExpression
//	ast.Inspect(astNode, func(n ast.Node) bool {
//	    if binExpr, ok := n.(*ast.BinaryExpression); ok {
//	        if binExpr.Operator == "AND" {
//	            andExprs = append(andExprs, binExpr)
//	        }
//	    }
//	    return true
//	})
//
// # SQL Feature Support
//
// Version 1.6.0 Feature Matrix:
//
// Core SQL Features:
//   - DDL: CREATE TABLE, ALTER TABLE, DROP TABLE, CREATE INDEX
//   - DML: SELECT, INSERT, UPDATE, DELETE with full expression support
//   - JOINs: All join types (INNER, LEFT, RIGHT, FULL, CROSS, NATURAL)
//   - Subqueries: Scalar subqueries, correlated subqueries, table subqueries
//   - CTEs: WITH clause, recursive CTEs, materialized/non-materialized hints
//   - Set Operations: UNION, EXCEPT, INTERSECT (with ALL modifier support)
//   - Window Functions: Complete SQL-99 window function support with frames
//
// Advanced SQL-99/SQL:2003 Features:
//   - GROUPING SETS, ROLLUP, CUBE: Advanced aggregation (SQL-99 T431)
//   - MERGE: MERGE INTO statements (SQL:2003 F312)
//   - FETCH: FETCH FIRST/NEXT clause (SQL-99 F861, F862)
//   - Materialized Views: CREATE/REFRESH MATERIALIZED VIEW
//   - TRUNCATE: TRUNCATE TABLE with RESTART/CONTINUE IDENTITY
//
// Expression Operators:
//   - BETWEEN: Range expressions with NOT modifier
//   - IN: Value list and subquery membership tests
//   - LIKE/ILIKE: Pattern matching with wildcards
//   - IS NULL/IS NOT NULL: Null checking
//   - EXISTS: Existential quantification over subqueries
//   - ANY/ALL: Quantified comparison predicates
//
// PostgreSQL Extensions (v1.6.0):
//   - LATERAL JOIN: Correlated table subqueries in FROM clause
//   - DISTINCT ON: PostgreSQL-specific row selection
//   - FILTER Clause: Conditional aggregation (aggregate FILTER (WHERE condition))
//   - RETURNING Clause: Return modified rows from INSERT/UPDATE/DELETE
//   - JSON/JSONB Operators: ->, ->>, #>, #>>, @>, <@, ?, ?|, ?&, #-
//   - NULLS FIRST/LAST: Explicit null ordering in ORDER BY
//
// # Statement Types
//
// DML Statements:
//
//   - SelectStatement: SELECT queries with full SQL-99 feature support
//     Fields: Columns, From, Joins, Where, GroupBy, Having, OrderBy, Limit, Offset, Fetch
//     New in v1.6.0: DistinctOnColumns (DISTINCT ON), Fetch (FETCH FIRST/NEXT)
//
//   - InsertStatement: INSERT INTO statements
//     Fields: TableName, Columns, Values, Query (INSERT...SELECT), Returning, OnConflict
//     New in v1.6.0: Returning clause support
//
//   - UpdateStatement: UPDATE statements
//     Fields: TableName, Updates, From, Where, Returning
//     New in v1.6.0: Returning clause support, FROM clause for PostgreSQL
//
//   - DeleteStatement: DELETE FROM statements
//     Fields: TableName, Using, Where, Returning
//     New in v1.6.0: Returning clause support, USING clause for PostgreSQL
//
// DDL Statements:
//
//   - CreateTableStatement: CREATE TABLE with constraints and partitioning
//   - CreateViewStatement: CREATE VIEW with column list
//   - CreateMaterializedViewStatement: CREATE MATERIALIZED VIEW (PostgreSQL)
//   - CreateIndexStatement: CREATE INDEX with partial indexes and expressions
//   - AlterTableStatement: ALTER TABLE with multiple action types
//   - DropStatement: DROP TABLE/VIEW/INDEX with CASCADE/RESTRICT
//
// Advanced Statements:
//
//   - MergeStatement: MERGE INTO for upsert operations (SQL:2003 F312)
//     New in v1.6.0: Complete MERGE support with MATCHED/NOT MATCHED clauses
//
//   - TruncateStatement: TRUNCATE TABLE with identity control
//     New in v1.6.0: RESTART/CONTINUE IDENTITY, CASCADE/RESTRICT options
//
//   - RefreshMaterializedViewStatement: REFRESH MATERIALIZED VIEW
//     New in v1.6.0: CONCURRENTLY option for non-blocking refresh
//
// # Expression Types
//
// Basic Expressions:
//
//   - Identifier: Column or table names, optionally qualified (table.column)
//   - LiteralValue: Integer, float, string, boolean, NULL literals
//   - AliasedExpression: Expressions with aliases (expr AS alias)
//
// Operator Expressions:
//
//   - BinaryExpression: Binary operations (=, <, >, +, -, *, /, AND, OR, etc.)
//     New in v1.6.0: CustomOp field for PostgreSQL custom operators
//     JSON/JSONB operators: ->, ->>, #>, #>>, @>, <@, ?, ?|, ?&, #-
//
//   - UnaryExpression: Unary operations (NOT, -, +, etc.)
//     Supports PostgreSQL-specific operators: ~, |/, ||/, !, !!, @
//
//   - BetweenExpression: Range expressions (expr BETWEEN lower AND upper)
//
//   - InExpression: Membership tests (expr IN (values) or expr IN (subquery))
//
// Function and Aggregate Expressions:
//
//   - FunctionCall: Function calls with OVER clause for window functions
//     Fields: Name, Arguments, Over (WindowSpec), Distinct, Filter, OrderBy
//     New in v1.6.0: Filter field for FILTER clause (aggregate FILTER (WHERE condition))
//     New in v1.6.0: OrderBy field for aggregate functions (STRING_AGG, ARRAY_AGG)
//
//   - WindowSpec: Window specifications (PARTITION BY, ORDER BY, frame clause)
//     Fields: Name, PartitionBy, OrderBy, FrameClause
//
//   - WindowFrame: Frame specifications (ROWS/RANGE with bounds)
//     Fields: Type (ROWS or RANGE), Start, End (WindowFrameBound)
//
//   - WindowFrameBound: Frame boundary specifications
//     Types: CURRENT ROW, UNBOUNDED PRECEDING/FOLLOWING, n PRECEDING/FOLLOWING
//
// Subquery Expressions:
//
//   - SubqueryExpression: Scalar subqueries (SELECT returning single value)
//   - ExistsExpression: EXISTS (subquery) predicates
//   - AnyExpression: expr op ANY (subquery) quantified comparisons
//   - AllExpression: expr op ALL (subquery) quantified comparisons
//
// Conditional Expressions:
//
//   - CaseExpression: CASE WHEN ... THEN ... ELSE ... END expressions
//     Fields: Value (optional), WhenClauses, ElseClause
//
//   - CastExpression: CAST(expr AS type) type conversions
//
// Advanced Grouping Expressions (SQL-99 T431):
//
//   - RollupExpression: ROLLUP(cols) for hierarchical grouping
//     Generates grouping sets: (a,b,c), (a,b), (a), ()
//
//   - CubeExpression: CUBE(cols) for all grouping combinations
//     Generates all possible grouping sets from columns
//
//   - GroupingSetsExpression: GROUPING SETS(...) for explicit grouping sets
//     Allows arbitrary specification of grouping combinations
//
// SQL-99 Features:
//
//   - FetchClause: FETCH FIRST/NEXT n ROWS ONLY/WITH TIES (SQL-99 F861, F862)
//     Fields: OffsetValue, FetchValue, FetchType, IsPercent, WithTies
//
//   - OrderByExpression: ORDER BY with NULLS FIRST/LAST (SQL-99 F851)
//     Fields: Expression, Ascending, NullsFirst
//
// # Common Table Expressions (CTEs)
//
// WithClause: WITH clause for Common Table Expressions
//
//	type WithClause struct {
//	    Recursive bool                 // RECURSIVE keyword
//	    CTEs      []*CommonTableExpr   // List of CTEs
//	}
//
// CommonTableExpr: Individual CTE definition
//
//	type CommonTableExpr struct {
//	    Name         string      // CTE name
//	    Columns      []string    // Optional column list
//	    Statement    Statement   // CTE query
//	    Materialized *bool       // nil=default, true=MATERIALIZED, false=NOT MATERIALIZED
//	}
//
// New in v1.6.0: Materialized field for PostgreSQL optimization hints
//
// Example CTE Structure:
//
//	WITH RECURSIVE employee_tree (id, name, manager_id, level) AS (
//	    SELECT id, name, manager_id, 1 FROM employees WHERE manager_id IS NULL
//	    UNION ALL
//	    SELECT e.id, e.name, e.manager_id, t.level + 1
//	    FROM employees e JOIN employee_tree t ON e.manager_id = t.id
//	)
//	SELECT * FROM employee_tree ORDER BY level;
//
// # Set Operations
//
// SetOperation: UNION, EXCEPT, INTERSECT operations
//
//	type SetOperation struct {
//	    Left     Statement  // Left statement
//	    Operator string     // UNION, EXCEPT, INTERSECT
//	    Right    Statement  // Right statement
//	    All      bool       // ALL modifier (UNION ALL vs UNION)
//	}
//
// Set operations support left-associative parsing for multiple operations:
//
//	SELECT * FROM t1 UNION SELECT * FROM t2 EXCEPT SELECT * FROM t3
//	Parsed as: (t1 UNION t2) EXCEPT t3
//
// # Window Functions
//
// Complete SQL-99 window function support with frame specifications:
//
// WindowSpec: Defines window for function evaluation
//
//	type WindowSpec struct {
//	    Name        string                // Optional window name
//	    PartitionBy []Expression          // PARTITION BY clause
//	    OrderBy     []OrderByExpression   // ORDER BY clause
//	    FrameClause *WindowFrame          // Frame specification
//	}
//
// WindowFrame: Frame clause (ROWS/RANGE)
//
//	type WindowFrame struct {
//	    Type  string            // ROWS or RANGE
//	    Start WindowFrameBound  // Starting bound
//	    End   *WindowFrameBound // Optional ending bound
//	}
//
// WindowFrameBound: Frame boundary specification
//
//	type WindowFrameBound struct {
//	    Type  string      // CURRENT ROW, UNBOUNDED PRECEDING, etc.
//	    Value Expression  // For n PRECEDING/FOLLOWING
//	}
//
// Example Window Function Query:
//
//	SELECT
//	    name,
//	    salary,
//	    ROW_NUMBER() OVER (ORDER BY salary DESC) as rank,
//	    AVG(salary) OVER (
//	        PARTITION BY department
//	        ORDER BY hire_date
//	        ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
//	    ) as rolling_avg
//	FROM employees;
//
// # JOIN Support
//
// JoinClause: All SQL join types with proper precedence
//
//	type JoinClause struct {
//	    Type      string          // INNER, LEFT, RIGHT, FULL, CROSS, NATURAL
//	    Left      TableReference  // Left table
//	    Right     TableReference  // Right table
//	    Condition Expression      // ON condition or USING clause
//	}
//
// TableReference: Table reference with subquery and LATERAL support
//
//	type TableReference struct {
//	    Name     string           // Table name
//	    Alias    string           // Optional alias
//	    Subquery *SelectStatement // Derived table (subquery)
//	    Lateral  bool             // LATERAL keyword (PostgreSQL v1.6.0)
//	}
//
// New in v1.6.0: Lateral field enables correlated subqueries in FROM clause
//
// Example LATERAL JOIN (PostgreSQL):
//
//	SELECT u.name, r.order_date
//	FROM users u,
//	LATERAL (
//	    SELECT * FROM orders
//	    WHERE user_id = u.id
//	    ORDER BY order_date DESC
//	    LIMIT 3
//	) r;
//
// # PostgreSQL Extensions (v1.6.0)
//
// DISTINCT ON: PostgreSQL-specific row selection
//
//	type SelectStatement struct {
//	    DistinctOnColumns []Expression  // DISTINCT ON (expr, ...)
//	    // ... other fields
//	}
//
// Example:
//
//	SELECT DISTINCT ON (dept_id) dept_id, name, salary
//	FROM employees
//	ORDER BY dept_id, salary DESC;
//
// FILTER Clause: Conditional aggregation
//
//	type FunctionCall struct {
//	    Filter Expression  // WHERE clause for aggregate functions
//	    // ... other fields
//	}
//
// Example:
//
//	SELECT
//	    COUNT(*) FILTER (WHERE status = 'active') AS active_count,
//	    SUM(amount) FILTER (WHERE type = 'credit') AS total_credits
//	FROM transactions;
//
// RETURNING Clause: Return modified rows
//
//	type InsertStatement struct {
//	    Returning []Expression  // RETURNING clause
//	    // ... other fields
//	}
//
// Example:
//
//	INSERT INTO users (name, email)
//	VALUES ('John', 'john@example.com')
//	RETURNING id, created_at;
//
// JSON/JSONB Operators: PostgreSQL JSON/JSONB operations
//
//	BinaryExpression operators:
//	  -> (Arrow)           : JSON field/array element access
//	  ->> (LongArrow)      : JSON field/array element access as text
//	  #> (HashArrow)       : JSON path access
//	  #>> (HashLongArrow)  : JSON path access as text
//	  @> (AtArrow)         : JSON contains operator
//	  <@ (ArrowAt)         : JSON contained by operator
//	  ? (Question)         : JSON key exists
//	  ?| (QuestionPipe)    : JSON any key exists
//	  ?& (QuestionAnd)     : JSON all keys exist
//	  #- (HashMinus)       : JSON delete operator
//
// Example:
//
//	SELECT
//	    data->>'name' AS name,
//	    data->'address'->>'city' AS city,
//	    data #> '{tags, 0}' AS first_tag
//	FROM users
//	WHERE data @> '{"active": true}'
//	  AND data ? 'email';
//
// # Operator Support
//
// UnaryOperator: Unary operators for expressions
//
//	const (
//	    Plus                UnaryOperator = iota  // +expr
//	    Minus                                     // -expr
//	    Not                                       // NOT expr
//	    PGBitwiseNot                              // ~expr (PostgreSQL)
//	    PGSquareRoot                              // |/expr (PostgreSQL)
//	    PGCubeRoot                                // ||/expr (PostgreSQL)
//	    PGPostfixFactorial                        // expr! (PostgreSQL)
//	    PGPrefixFactorial                         // !!expr (PostgreSQL)
//	    PGAbs                                     // @expr (PostgreSQL)
//	    BangNot                                   // !expr (Hive)
//	)
//
// BinaryOperator: Binary operators for expressions
//
//	const (
//	    // Arithmetic operators
//	    BinaryPlus, BinaryMinus, Multiply, Divide, Modulo
//
//	    // Comparison operators
//	    Eq, NotEq, Lt, Gt, LtEq, GtEq, Spaceship
//
//	    // Logical operators
//	    And, Or, Xor
//
//	    // String/Array operators
//	    StringConcat  // ||
//
//	    // Bitwise operators
//	    BitwiseAnd, BitwiseOr, BitwiseXor
//	    PGBitwiseXor, PGBitwiseShiftLeft, PGBitwiseShiftRight
//
//	    // PostgreSQL-specific operators
//	    PGExp, PGOverlap, PGRegexMatch, PGRegexIMatch
//	    PGRegexNotMatch, PGRegexNotIMatch, PGStartsWith
//
//	    // JSON/JSONB operators (PostgreSQL v1.6.0)
//	    Arrow, LongArrow, HashArrow, HashLongArrow
//	    AtArrow, ArrowAt, Question, QuestionAnd, QuestionPipe, HashMinus
//
//	    // Other operators
//	    Overlaps  // SQL OVERLAPS for datetime periods
//	)
//
// CustomBinaryOperator: PostgreSQL custom operators
//
//	type CustomBinaryOperator struct {
//	    Parts []string  // Operator parts for schema-qualified operators
//	}
//
// Example: OPERATOR(schema.custom_op)
//
// # MERGE Statement (SQL:2003 F312)
//
// MergeStatement: MERGE INTO for upsert operations
//
//	type MergeStatement struct {
//	    TargetTable TableReference     // Table being merged into
//	    TargetAlias string             // Optional target alias
//	    SourceTable TableReference     // Source table or subquery
//	    SourceAlias string             // Optional source alias
//	    OnCondition Expression         // Join/match condition
//	    WhenClauses []*MergeWhenClause // WHEN clauses
//	}
//
// MergeWhenClause: WHEN clause in MERGE
//
//	type MergeWhenClause struct {
//	    Type      string       // MATCHED, NOT_MATCHED, NOT_MATCHED_BY_SOURCE
//	    Condition Expression   // Optional AND condition
//	    Action    *MergeAction // UPDATE, INSERT, or DELETE action
//	}
//
// MergeAction: Action in MERGE WHEN clause
//
//	type MergeAction struct {
//	    ActionType    string       // UPDATE, INSERT, DELETE
//	    SetClauses    []SetClause  // For UPDATE
//	    Columns       []string     // For INSERT
//	    Values        []Expression // For INSERT
//	    DefaultValues bool         // INSERT DEFAULT VALUES
//	}
//
// Example MERGE statement:
//
//	MERGE INTO target_table t
//	USING source_table s ON t.id = s.id
//	WHEN MATCHED THEN
//	    UPDATE SET t.name = s.name, t.value = s.value
//	WHEN NOT MATCHED THEN
//	    INSERT (id, name, value) VALUES (s.id, s.name, s.value);
//
// # Memory Management and Performance
//
// The ast package is designed for high-performance SQL parsing with minimal
// memory allocations. Key performance features:
//
// Object Pooling:
//   - sync.Pool for all major AST node types
//   - 60-80% memory reduction in production workloads
//   - 95%+ pool hit rates with proper usage patterns
//   - Zero-copy semantics where possible
//
// Performance Characteristics:
//   - 1.38M+ operations/second sustained throughput
//   - Up to 1.5M ops/sec peak performance
//   - <1μs latency for complex queries with window functions
//   - Thread-safe: Zero race conditions (validated with 20,000+ concurrent operations)
//
// Memory Safety:
//   - Iterative cleanup to prevent stack overflow with deeply nested expressions
//   - Configurable recursion depth limits (MaxCleanupDepth = 100)
//   - Work queue size limits (MaxWorkQueueSize = 1000)
//
// Pool Configuration Constants:
//
//	const (
//	    MaxCleanupDepth  = 100   // Prevents stack overflow in cleanup
//	    MaxWorkQueueSize = 1000  // Limits work queue for iterative cleanup
//	)
//
// # Thread Safety
//
// All AST operations are thread-safe and race-free:
//
//   - Object pools use sync.Pool (thread-safe by design)
//   - All node types are immutable after construction
//   - No shared mutable state between goroutines
//   - Validated with comprehensive concurrent testing (20,000+ operations)
//
// # Usage Examples
//
// Example 1: Building a SELECT statement with pooling
//
//	// Get statement from pool
//	stmt := ast.GetSelectStatement()
//	defer ast.PutSelectStatement(stmt)
//
//	// Build column list
//	col1 := ast.GetIdentifier()
//	col1.Name = "id"
//	col2 := ast.GetIdentifier()
//	col2.Name = "name"
//	stmt.Columns = []ast.Expression{col1, col2}
//
//	// Add WHERE clause
//	whereExpr := ast.GetBinaryExpression()
//	whereExpr.Operator = "="
//	whereExpr.Left = ast.GetIdentifier()
//	whereExpr.Left.(*ast.Identifier).Name = "active"
//	whereExpr.Right = ast.GetLiteralValue()
//	whereExpr.Right.(*ast.LiteralValue).Value = true
//	whereExpr.Right.(*ast.LiteralValue).Type = "BOOLEAN"
//	stmt.Where = whereExpr
//
//	// Use the statement
//	// ... process statement ...
//
// Example 2: Creating a window function expression
//
//	// Build function call with window specification
//	fnCall := ast.GetFunctionCall()
//	fnCall.Name = "ROW_NUMBER"
//	fnCall.Over = &ast.WindowSpec{
//	    OrderBy: []ast.OrderByExpression{
//	        {
//	            Expression: &ast.Identifier{Name: "salary"},
//	            Ascending:  false, // DESC
//	        },
//	    },
//	}
//
// Example 3: Traversing AST to find all tables
//
//	var tables []string
//	ast.Inspect(astNode, func(n ast.Node) bool {
//	    if ref, ok := n.(*ast.TableReference); ok {
//	        if ref.Name != "" {
//	            tables = append(tables, ref.Name)
//	        }
//	    }
//	    return true
//	})
//	fmt.Printf("Tables referenced: %v\n", tables)
//
// Example 4: PostgreSQL JSON operator expression
//
//	// data->>'email' expression
//	jsonExpr := ast.GetBinaryExpression()
//	jsonExpr.Left = &ast.Identifier{Name: "data"}
//	jsonExpr.Operator = "->>"
//	jsonExpr.Right = &ast.LiteralValue{Value: "email", Type: "STRING"}
//
// Example 5: Building a CTE with materialization hint
//
//	cte := &ast.CommonTableExpr{
//	    Name:    "active_users",
//	    Columns: []string{"id", "name", "email"},
//	    Statement: selectStmt,
//	    Materialized: &trueVal, // MATERIALIZED hint
//	}
//
//	withClause := &ast.WithClause{
//	    Recursive: false,
//	    CTEs:      []*ast.CommonTableExpr{cte},
//	}
//
// # Testing and Validation
//
// The ast package has comprehensive test coverage:
//
//   - 73.4% code coverage (AST nodes with edge case testing)
//   - 100% coverage for models package (underlying data structures)
//   - Thread safety validated with race detection (20,000+ concurrent ops)
//   - Memory leak testing with extended load tests
//   - Performance benchmarks for all major operations
//
// # Version History
//
// v1.0.0 - Initial release:
//   - Basic DML statements (SELECT, INSERT, UPDATE, DELETE)
//   - DDL statements (CREATE TABLE, ALTER TABLE, DROP TABLE)
//   - Expression support (binary, unary, literals)
//
// v1.1.0 - Phase 1 JOINs:
//   - All JOIN types (INNER, LEFT, RIGHT, FULL, CROSS, NATURAL)
//   - USING clause support
//   - Left-associative JOIN parsing
//
// v1.2.0 - Phase 2 CTEs and Set Operations:
//   - WITH clause for CTEs
//   - Recursive CTEs
//   - UNION, EXCEPT, INTERSECT operations
//   - Set operation precedence handling
//
// v1.3.0 - Phase 2.5 Window Functions:
//   - WindowSpec for window specifications
//   - WindowFrame for frame clauses (ROWS/RANGE)
//   - WindowFrameBound for boundary specifications
//   - FunctionCall.Over for window functions
//
// v1.4.0 - Advanced Grouping:
//   - GROUPING SETS, ROLLUP, CUBE (SQL-99 T431)
//   - Enhanced GROUP BY expressions
//
// v1.5.0 - MERGE and Views:
//   - MERGE statement (SQL:2003 F312)
//   - CREATE MATERIALIZED VIEW
//   - REFRESH MATERIALIZED VIEW
//
// v1.6.0 - PostgreSQL Extensions:
//   - LATERAL JOIN support (TableReference.Lateral)
//   - DISTINCT ON clause (SelectStatement.DistinctOnColumns)
//   - FILTER clause for aggregates (FunctionCall.Filter)
//   - RETURNING clause (InsertStatement/UpdateStatement/DeleteStatement.Returning)
//   - JSON/JSONB operators (Arrow, LongArrow, HashArrow, etc.)
//   - FETCH FIRST/NEXT clause (FetchClause)
//   - TRUNCATE statement with identity control
//   - Materialized CTE hints (CommonTableExpr.Materialized)
//   - Aggregate ORDER BY (FunctionCall.OrderBy)
//   - NULLS FIRST/LAST (OrderByExpression.NullsFirst)
//
// # Related Packages
//
//   - pkg/sql/parser: Recursive descent parser that builds AST nodes
//   - pkg/sql/tokenizer: Zero-copy tokenizer for SQL input
//   - pkg/models: Core data structures (tokens, spans, locations)
//   - pkg/errors: Structured error handling with position information
//
// # References
//
//   - SQL-99 Standard: ISO/IEC 9075:1999 (window functions, CTEs)
//   - SQL:2003 Standard: ISO/IEC 9075:2003 (MERGE, FILTER clause)
//   - PostgreSQL Documentation: https://www.postgresql.org/docs/
//   - MySQL Documentation: https://dev.mysql.com/doc/
//
// # License
//
// Copyright (c) 2024 GoSQLX Contributors
// Licensed under the Apache License, Version 2.0
package ast
