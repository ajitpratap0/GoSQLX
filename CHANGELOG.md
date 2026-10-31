# Changelog

All notable changes to GoSQLX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **AST**: `AlterTableStatement.SQL()` now separates multiple ALTER TABLE actions with commas, matching the compact formatter and preserving action boundaries when re-parsed.
- **Playground**: the GoSQLX WebAssembly module now runs in a Web Worker, so
  loading the parser and every parse, format, lint, analyze, highlight and
  transpile call no longer block the page. The playground computes only the
  open tab (plus lint, which marks errors in the editor) and the rest when a
  tab is opened. Total Blocking Time on `/playground/` dropped from ~490 ms to
  ~80 ms in local Lighthouse runs at CI-equivalent CPU throttling, which ends
  the Lighthouse CI performance failures on slower GitHub runners.

## [1.17.0] - 2026-10-31 — Real-World Dialect Corpus, Dialect-Faithful Round Trips, Security Scanner & LSP Hardening

Covers everything merged since v1.16.0, mostly the October 2026 dialect audit:
a 2,813-statement real-world corpus across eight dialects that now parses,
formats, re-parses identically and keeps every word, guarded by a ratchet test;
new syntax across Snowflake, BigQuery, ClickHouse, SQL Server, MySQL/MariaDB
and PostgreSQL; per-dialect lexing and rendering (numeric and Unicode-escape
literals, `#` comments, quoted identifiers, SQL Server `GO` and Oracle `/`
lines); safer transpilation; a hardened `ScanSQL` and an AST scanner that
walks the whole tree; and an LSP server that advertises the spec's
`textDocumentSync` key and survives malformed input.
The release is source-compatible: exported signatures are unchanged apart from
additions. Runtime behaviour does change (parse acceptance per dialect, SQL
Server `GO` and `top`, statement termination, numeric lexing, fingerprints,
statement counts, LSP capabilities), so read **Behavior changes** before
upgrading.

### Behavior changes
- **SQL Server `GO` inside a statement is an error**: a line holding only
  `GO [n]` inside a statement is now a parse error ("GO batch separator inside
  a statement"), matching sqlcmd, instead of a column or alias named `go`.
  `GO 0` / `GO 1.5` alone on a line report "invalid GO repeat count". (#868)
- **`AST.Statements` holds batch separators**: SQL Server `GO` is kept as an
  `*ast.BatchSeparator` node (with its optional `RepeatCount`; repeated batches
  are not expanded) instead of being discarded. Code that iterates
  `AST.Statements` or recovery results must skip these nodes. Statement counts
  (`gosqlx analyze`, `gosqlx parse`, the MCP `parse_sql` tool and the C
  binding's `statement_count` / statement types) exclude them. (#867)
- **SQL Server `top` is reserved**: unquoted `top` (any case) is a syntax
  error where a table name, INSERT/UPDATE/DELETE/MERGE target, table alias or
  select-item alias is expected (`SELECT * FROM top`, `INSERT INTO top ...`);
  quote it as `[top]`. (#880)
- **Statements end at their grammar**: outside SQL Server, a utility statement
  (`SET`, `USE`, `GRANT`, `COPY`, `CALL`, ...) followed on the next line by
  another statement without `;` is an error; only a transaction statement on
  its own line is accepted without a separator. Statements whose definition
  holds a statement (`PREPARE ... AS`, `DECLARE ... CURSOR FOR`, `CREATE
  FUNCTION`/`PROCEDURE`/`TRIGGER`/`EVENT`/`RULE`/`TASK`/`VIEW` with a
  single-statement, `RETURN` or `BEGIN ... END` body, `LOAD DATA`) end with
  that definition, and `GRANT`, `REVOKE`, PostgreSQL `COPY`, `CALL`, `VACUUM`,
  `ANALYZE`, `LISTEN`, `UNLISTEN` and `NOTIFY` end with their grammar, so
  trailing tokens or a following statement without `;` are an error on the
  same line as well (`VACUUM t junk`, `LISTEN c extra`). MySQL / MariaDB /
  Oracle `ANALYZE TABLE` keeps its as-written handling. (#867, #872, #878)
- **Utility statements are gated per dialect**: they are accepted only in the
  dialects that have them (`VACUUM` in PostgreSQL/SQLite,
  `LISTEN`/`NOTIFY`/`CLUSTER`/`DISCARD` in PostgreSQL,
  `FLUSH`/`OPTIMIZE`/`LOCK TABLES`/`KILL` in the MySQL family, `PRAGMA` in
  SQLite, `DO $$ ... $$` in PostgreSQL, `LOAD DATA` in the MySQL family and
  BigQuery, `SHOW` not in SQLite/SQL Server/Oracle, no `SET`/`GRANT` in
  SQLite, ...); a parser without a dialect still accepts all of them. (#872)
- **Per-dialect grammar checks**: transaction statements are checked against
  each dialect's grammar (`BEGIN banana` is rejected); `<=>` is accepted only
  in MySQL, MariaDB and PostgreSQL (pgvector) and `==` only in SQLite and
  ClickHouse; an unbalanced SQL Server `BEGIN ... END` block, or an
  `IF`/`WHILE` without a body, is an error. MySQL / MariaDB `:=` inside an
  expression assigns only to a user variable (`SELECT @v := 1`); `f(a := 1)`
  and `arr[1:=2]` are errors. PostgreSQL `f(a := 1)` parses as a named
  argument, written back as `f(a => 1)`. (#867, #872)
- **Numeric literals are lexed per dialect**: numeric words without
  whitespace no longer silently become a number plus a column alias, and
  numeric spelling is retained. Differences from the previous lexer (#874):

  | Dialect | Numeric changes | Unicode-escape changes |
  | --- | --- | --- |
  | PostgreSQL | `1_000`, `1_000.000_1`, `0o17`, `0b101`, and base-prefix separators such as `0x_FF` are single numbers. Malformed forms (`1x`, `0x`, `1__0`, `1_`, `1FROM`) error. | `U&'...'` with optional `UESCAPE` (comments allowed before it) is validated and preserved as one literal; `U&"..."` decodes to a quoted identifier usable wherever a name is. Malformed escapes error. |
  | MySQL / MariaDB | `0b101` is a single bit literal; `1x`, `1_000`, and bare `0x` are identifiers rather than number/alias pairs. A number with a fraction still ends before a name (`1.5a` is `1.5 AS a`). | Unchanged: `U&'x'` remains separate `U`, `&`, and string tokens. |
  | SQLite | `1_000` is one number; numeric trailing junk and unsupported `0b101` error. | Unchanged. |
  | ClickHouse | `1_000` and `0b101` are single numbers; numeric trailing junk errors. | Unchanged. |
  | SQL Server | Numeric trailing junk, including `1_000` and `0b101`, errors; a keyword written against a number (`1AS x`) is still accepted. | Unchanged. |
  | Oracle | `1d`, `1.5f`, `1e5D` (BINARY_DOUBLE/BINARY_FLOAT) are single numbers. Storage sizes (`100M`, `8K`, `2G`) keep their units wherever a size appears; keywords against a number (`1FROM`) are accepted; other trailing junk, `1_000` and `0b101` error. | Unchanged. |
  | Snowflake / BigQuery / Redshift | Numeric trailing junk, `0b101` and `1_000` error. | Unchanged. |
  | generic | As Oracle for storage sizes and keywords; `1d`, `1x`, `1_000`, `0b101` error. | Unchanged. |

  `0x1F` remains a single hex literal in every dialect.
- **MySQL / MariaDB `#` line comments**: with the MySQL or MariaDB dialect, `#`
  starts a line comment, like `--`. The tokenizer records it in `Comments`
  (re-emitted by the formatter), `SplitStatements` no longer splits on a `;`
  inside it, and transpiling to another dialect drops it instead of emitting
  `#` (PostgreSQL XOR). Previously `WHERE x = 1 # c` parsed `#` as an operator
  and `SELECT a FROM t # c` failed with E2002. Other dialects keep their `#`
  meaning (PostgreSQL `#`, `#>`, `#>>`, `#-`; SQL Server `#temp`; Oracle
  `emp#`). (#881)
- **Unrepresentable string bytes are errors**: a raw NUL or Ctrl-Z byte inside
  a string literal is an error in dialects whose literals cannot spell it back
  (NUL without backslash escapes; both without a dialect; Ctrl-Z in
  ClickHouse; both in Snowflake). Formatting used to drop or rewrite it,
  changing the value. (#867)
- **Fingerprints keep identifier quoting**: `fingerprint.Normalize` and
  `Fingerprint` keep identifier quoting (`SELECT "A" FROM "T"` used to
  normalize to `SELECT A FROM T`), so fingerprints of queries with quoted
  identifiers differ from earlier releases. Re-compute stored fingerprints
  after upgrading. (#867)
- **`gosqlx.Lint` / `LintWithDialect` report invalid SQL**: SQL that does not
  tokenize or parse returns an error wrapping `ErrTokenize` or `ErrSyntax`
  together with the violations of the text and token rules. Callers that
  ignored the error and treated an empty result as clean must now check it.
  `linter.FileResult` gains `TokenizeError`, `ParseError` and `SyntaxError()`;
  `gosqlx lint` exits 1 on syntax errors. (#867)
- **Formatting refuses to drop comments**: `gosqlx.Format` and `gosqlx format`
  keep comments and optimizer hints (see Fixed); input whose hints or MySQL
  `/*! ... */` comments cannot be placed faithfully is refused with
  `formatter.ErrUnplaceableComment` instead of being rewritten without them.
  (#867)
- **Transpilation refuses lossy output**: string literals and quoted
  identifiers are rendered with the target dialect's escape rules and
  delimiters, and unrepresentable literals return an error rather than
  changing their value. SQL Server `GO` scripts targeting another dialect,
  operators the target cannot express, `LIMIT` on a set operation without
  `ORDER BY` for SQL Server, `TOP ... PERCENT` / `WITH TIES` where the target
  has no equivalent, and rewrites nested deeper than 512 levels return an
  error instead of emitting changed or invalid SQL. (#867, #874, #876, #883,
  #887)
- **PIVOT / UNPIVOT `IN` lists** require commas between entries and an alias
  after `AS` in every PIVOT dialect. Where bare aliases are supported,
  `IN (a b)` is one entry (`a AS b`); otherwise a missing comma is rejected.
  `IN ('a' AS)` no longer silently drops the `AS`. Numeric UNPIVOT row aliases
  after `AS` are limited to BigQuery and Oracle. (#857)
- **LSP capabilities key**: `initialize` advertises `textDocumentSync`, as the
  LSP specification requires, instead of the non-standard
  `textDocumentSyncOptions`; unknown methods are answered with `-32601`
  (MethodNotFound) instead of `-32603`. Clients that read the old key must
  switch. (#882, #887)

### Security
- **`ScanSQL` bypasses closed**: the string scanner (also used by MCP, the C
  binding and WASM) matches comments between keywords (`UNION/**/SELECT`,
  `SLEEP/**/(5)`, `;--\nDROP`, `#` comments, `/*/`, MySQL `1--1`) through
  comment-free views of the text under each quoting and escaping convention,
  and scans MySQL/MariaDB `/*! */` and `/*M! */` bodies. Dollar-quote stripping
  no longer runs inside quoted strings or identifiers. Tautology and comment
  checks cover the whole input instead of the first 10,000 bytes, and inputs
  above 10 MiB get a CRITICAL `INPUT_TOO_LARGE` finding whatever the severity
  filter. (#885)
- **`Scanner.Scan(tree)` walks the whole AST**: time-based, out-of-band and
  tautology patterns are detected inside CTEs, derived tables and subqueries,
  CASE/CAST/IN/BETWEEN/ANY, ORDER BY/GROUP BY, JOIN ON, window specs, FILTER,
  LIMIT, LATERAL/APPLY, PREWHERE, QUALIFY, CONNECT BY, RETURNING, ON CONFLICT,
  INSERT ... SELECT, MERGE, CREATE TABLE AS, CREATE [MATERIALIZED] VIEW and
  EXPLAIN, matching `ScanSQL`. UNION injection checks also run on set
  operations nested in CTEs and subqueries, and the UNION NULL-padding check
  matches the parser's NULL literal. Qualified column comparisons such as
  `a.id = b.id` are no longer reported as tautologies. (#879, #885)
- **Raw-text statements are scanned**: raw dialect statements and standalone
  `VALUES` are scanned for injection patterns. (#871)
- **CLI security scan merges both scanners**: `gosqlx analyze --security` and
  `gosqlx lint`'s security pass run `ScanSQL` as well as the AST scan and merge
  the findings, so `SELECT 1; DROP TABLE users` is reported as CRITICAL instead
  of clean. (#887)
- **C binding**: every C export recovers from panics and returns an error
  instead of crashing the host process. (#871)

### Added
- **Real-world dialect corpus**: `testdata/realworld/<dialect>/` holds 2,813
  production-style statements across PostgreSQL, MySQL, MariaDB, SQL Server,
  Oracle, SQLite, Snowflake and ClickHouse. `TestRealWorldCorpus` runs each
  through split, parse, format, reparse, idempotency and dropped-word checks
  against a ratchet list (`testdata/realworld/known_failures.txt`, regenerate
  with `-update-known-failures`): a new failure fails the test, and so does a
  listed failure that now passes. Every statement now passes and the list is
  empty (1,327 failures before). `scripts/dialect-audit` runs the same checks
  on any SQL file; `BenchmarkRealWorldParse` and `BenchmarkRealWorldParseFormat`
  measure the corpus. (#866, #867)
- **New syntax**: Snowflake PIVOT `DEFAULT ON NULL`, ClickHouse FINAL/SAMPLE
  (also on joined tables, `TableModifiers.Sample`; decimal sizes and offsets
  only, held in inspectable expression fields), SQL Server `INSERT TOP`, MySQL
  / MariaDB `ALTER TABLE` partition actions (ADD/DROP [IF [NOT] EXISTS],
  TRUNCATE, REORGANIZE, COALESCE, EXCHANGE, ANALYZE/CHECK/OPTIMIZE/REBUILD/
  REPAIR, DISCARD/IMPORT, REMOVE/UPGRADE PARTITIONING, ALL), PostgreSQL
  `ROWS FROM` and array subscripts, ROLLUP/CUBE/nested GROUPING SETS inside
  GROUPING SETS, and identity constraints (a column with more than one of
  DEFAULT, an identity clause and a generation expression is rejected).
  Partition actions outside the structured grammar still parse as as-written
  `AlterTableOther` text. (#873)
- **BigQuery PIVOT / UNPIVOT**: the parser gated PIVOT/UNPIVOT on a hard-coded
  SQL Server / Oracle / Snowflake list, so BigQuery rejected them with E2002
  although its capabilities advertise `SupportsPivotUnpivot`. The gate is now
  `Capabilities().SupportsPivotUnpivot` (true for exactly SQL Server, Oracle,
  Snowflake and BigQuery). Supported BigQuery forms: aggregate aliases and
  multiple aggregates, `IN` value aliases with or without `AS`,
  `UNPIVOT INCLUDE NULLS` / `EXCLUDE NULLS`, row-value aliases with or without
  `AS` (string or INT64) and multi-column UNPIVOT. Oracle also gets
  aliased/multiple aggregates, the NULLS modifier and multi-column UNPIVOT;
  Snowflake gets the NULLS modifier and bare `IN` value aliases. New
  `ast.PivotClause.AggregateAlias`, `ast.PivotClause.ExtraAggregates`
  (`[]ast.PivotAggregate`), `ast.UnpivotClause.NullHandling`,
  `ast.UnpivotClause.ValueColumns` and `ast.UnpivotNullHandling`; quoted
  aliases and value columns keep their source delimiters when rendered.
  (#857, fixes #854)
- **More statements**: MariaDB `DELETE HISTORY FROM t [PARTITION (p, ...)]
  [BEFORE SYSTEM_TIME [TIMESTAMP | TRANSACTION] expr]` (held in
  `ast.DMLTargetFields.History`, `ast.DeleteHistoryOptions`); PostgreSQL
  `ALTER DEFAULT PRIVILEGES [FOR ROLE r] [IN SCHEMA s] GRANT | REVOKE ...`.
  (#872, #880)
- **AST metadata for faithful rendering**: `ExplainStatement` retains the
  explained statement; `ast.BatchSeparator` retains SQL Server `GO`; string
  literals retain their introducer (`N`, `X`, `B`, `_utf8mb4`, ...) and escape
  rules (`LiteralValue.DialectExtras()`, `EnsureExtras()`,
  `SetRawBackslash()`); `Identifier.QuoteStyle`, `Identifier.Quotes` and the
  statement/table/column `NameQuote` fields retain identifier delimiters.
  `AST.StatementEnds`, `AST.ExecuteSlash` / `ExecuteSlashPositions` (Oracle
  SQL*Plus `/` lines) and `AST.UnicodeIdentifiers` (PostgreSQL `U&"..."`
  spellings) record source layout for the formatter. (#867, #869, #886)
- **Dialect extension fields**: dialect-specific clauses live behind optional
  pointers so that common statements do not carry them:
  `SelectStatement.Extras` (`SelectExtras`: SELECT modifiers, INTO, LIMIT BY,
  ROWS EXAMINED, INTERPOLATE, query hints, output formats),
  `InsertStatement.Extras`, `UpdateStatement.Extras` / `DeleteStatement.Extras`
  (`DMLTargetFields`: modifiers, TOP, ONLY, extra targets, joins, OUTPUT,
  ORDER BY / LIMIT, RETURNING INTO), `FunctionCall.Extras`,
  `BinaryExpression.Extras` and `TableReference.Modifiers` (including derived
  `VALUES`). Read them through `DialectExtras()` / `DialectModifiers()`, which
  return values for read access without shared mutable stand-ins; call
  `EnsureExtras()` / `EnsureModifiers()` before writing. (#867)
- **Formatter API**: `formatter.FormatASTChecked`, `FormatStatementChecked`
  and `FormatExpressionChecked` return an error for nodes they cannot render
  faithfully; `formatter.JoinWithComments`, `JoinASTWithComments`,
  `CommentLayout`, `BatchPositions` and `StatementPositions` re-attach
  comments to formatted statements; `EnsureStatementTerminator`,
  `ExecuteSlashStatement` and `RestoreUnicodeIdentifiers` keep terminators,
  Oracle `/` lines and `U&` spellings. `gosqlx.FormatWithDialect`,
  `gosqlx.WithComments()`, `gosqlx.FormatASTChecked`,
  `gosqlx.FormatTreeChecked`, `Tree.FormatChecked` and
  `transform.FormatSQLChecked` expose the same at the higher levels.
  (#867, #884, #886)
- **MCP**: the `parse_sql` tool accepts an optional `dialect`. The hosted
  server is described by `server.json`, and tagged releases publish it to the
  MCP Registry (`publish-mcp.yml`, `docs/MCP_REGISTRY.md`). (#859, #876)

### Changed
- **Transpiling dialect-specific operators**: `^` is exponentiation in
  PostgreSQL and bitwise XOR in MySQL, MariaDB and SQL Server (recorded as
  `BinaryExpression.BitwiseXor`). Exponentiation is written `POWER(a, b)`
  outside PostgreSQL; XOR keeps `^` with explicit grouping between the MySQL
  family and SQL Server, becomes `#` in PostgreSQL, `BITXOR()` in Snowflake and
  `bitXor()` in ClickHouse, and returns an error for Oracle, SQLite and the
  generic dialect. PostgreSQL `@`, `|/` and `||/` become `ABS()`, `SQRT()` and
  `CBRT()` (an error where CBRT is missing); PostgreSQL `#` (XOR), `~`,
  `<<`/`>>`, `&`/`|` and `||` (CONCAT in MySQL/MariaDB) are rewritten into the
  target's form; `!!`, `@>`, `?`, regex `~`, SQL Server money literals
  (`$5.00`, `$5`) and Snowflake object constants (`{'a': 1}`) return an error
  in dialects without them. PostgreSQL `@` (absolute value) is always written
  as `@ x`, and `@` directly followed by operator characters (`@-@`, `@-5`) is
  rejected, as PostgreSQL lexes it as one operator. (#867, #874)
- **SQL Server row limits when transpiling**: `SELECT TOP` limits are
  rewritten across dialects (refusing `PERCENT` and `WITH TIES` where the
  target cannot express them); `LIMIT n OFFSET m` and bare `OFFSET` without
  ORDER BY add `ORDER BY (SELECT NULL)`, and `FETCH FIRST` gains the required
  `OFFSET 0 ROWS`. A LIMIT on a whole UNION/INTERSECT/EXCEPT is emitted as
  `ORDER BY ... OFFSET n ROWS FETCH NEXT m ROWS ONLY` instead of `TOP` on the
  last branch (which silently changed results). Row limits inside derived
  tables, JOIN operands and scalar subqueries are rewritten for the target
  dialect, and `WITH TIES` survives set-operation tails. (#876, #883, #887)
- **SQL Server `[top]`**: a delimited `[top]` / `"top"` is a plain name (also
  in the select list, where it was read as the TOP clause) and keeps its
  delimiters on output. (#880)
- **`gosqlx watch`** respects `--dialect`, re-validates changed files and
  formats files in place with the CLI safety checks. (#876)
- **CLI**: `lint --auto-fix` judges the fixed text; `format --no-uppercase`
  lower-cases keywords, keyword operators and built-in function keywords;
  `postgres`, `pg`, `mssql`, `tsql` and `sqlite3` are accepted by every
  `--dialect` flag; errors are printed once and usage only for flag and
  argument errors; `validate --quiet` exits silently; `validate` names stdin
  `<stdin>` and validates `GO`/`DELIMITER` scripts and files over the token
  limit statement by statement; empty and comment-only input is valid for
  `validate`, `lint` and `format`; `-o` works for `parse` and `transpile`,
  `-f`/`-o` map onto `validate`'s output flags and are rejected where
  unsupported; `format` keeps a leading byte order mark; inline SQL that
  contains `/` (`UNION/**/SELECT`, `4 / 2`) is no longer mistaken for a file
  path; the transpile dialect help is corrected. (#867, #876, #887)

### Fixed
- **Formatter fidelity**: `gosqlx.Format` and `gosqlx format` keep comments
  (a comment inside a statement moves to the line above it) and `/*+ ... */`
  hints directly after a statement's first keyword; `format -i` verifies that
  the output holds exactly the input's comments; LSP and C-binding dialect
  formatting no longer drop comments. Oracle SQL*Plus `/` execute lines are
  kept by `FormatAST`, `Formatter.Format`, `FormatWithDialect` and `gosqlx
  format` (they were dropped, and the CLI refused such scripts). PostgreSQL
  `U&"..."` identifiers keep their original spelling when formatting for
  PostgreSQL or no target (other targets get the decoded name), so names with
  escaped control characters no longer produce output that fails to
  re-tokenize. Comments next to SQL Server `GO` lines and trailing comments of
  statements written without `;` stay where they were, and `GO 2 /* c */`
  keeps both count and comment. Lower-case mode covers expression and
  built-in function keywords, and raw `JSON_TABLE`/`XMLTABLE` clauses retain
  their source case. (#867, #870, #886)
- **Format terminators**: with `AddSemicolon` and a comment anywhere in the
  input, raw-text statements (PostgreSQL `DO $$...$$`, `CREATE FUNCTION`
  bodies, Oracle `BEGIN ... END` blocks) lost their `;`, so the output no
  longer parsed or merged two statements. The comment-preserving path now adds
  terminators the same way as the plain path. (#884)
- **SQL round trips**: `SQL()`, `FormatAST` and `Transpile` preserve ALTER
  actions, grouped joins, set-operation query tails, CTE placement (a WITH
  clause before nested parenthesized set operands stays in front of the whole
  operation), standalone VALUES, JSON_TABLE/XMLTABLE literal quoting, quoted
  type names, and optimizer hints in subqueries (when the hinted SELECT cannot
  be identified, formatting fails with `ErrUnplaceableComment`). Hint
  placement uses the source dialect's lexer, so a keyword inside a string or
  quoted identifier is never a hint slot. `AST.SQL()` no longer drops
  `CREATE`/`ALTER`/`DROP SEQUENCE` statements, MERGE keeps the source's column
  alias list (`USING (VALUES ...) AS s (id, val)`), JSON/power operator
  precedence is correct, and hand-built expression trees (including hand-built
  operands inserted into parsed trees) render the parentheses they need.
  Formatting fixes MySQL join comma spacing and SELECT alias qualifiers.
  (#867, #870, #874)
- **Statement splitting**: `SplitStatements` keeps compound statements whole:
  `BEGIN ... END` blocks (trigger, procedure and function bodies, T-SQL
  `IF ... BEGIN`, `BEGIN TRY`, PostgreSQL `BEGIN ATOMIC`), `CASE ... END`,
  `IF`/`LOOP`/`WHILE`/`REPEAT` inside a block and Oracle `DECLARE`/`IS`/`AS`
  sections are no longer cut at the first inner `;`. Transaction statements
  (`BEGIN;`, `BEGIN TRANSACTION`, `BEGIN IMMEDIATE`) are not blocks, and a
  script whose blocks do not balance falls back to plain `;` splitting. Client
  batch separators are honoured and removed from the output: a `GO [n]` line
  for SQL Server, `DELIMITER` for MySQL/MariaDB and a lone `/` line for
  Oracle. Splitting follows dialect string escapes, parenthesized bodies and
  commented `GO` lines, agreeing with the parser. `ParseReaderMultiple` skips
  segments that hold only comments. (#867, #869)
- **Parser**: a T-SQL `IF ... ELSE IF ...` chain of any length is one
  statement, parsed in linear time (chains over ~100 branches hit the
  recursion limit and swallowed the next statement); MariaDB ``DELETE
  `history` FROM history`` stays a multi-table delete when formatted; MySQL
  `ANALYZE TABLE t UPDATE HISTOGRAM ...` and Oracle `ANALYZE TABLE t DELETE
  STATISTICS` are no longer read as MariaDB's `ANALYZE <statement>`;
  `GRANT ... TO [`, `TO [AppUser`, `TO CURRENT_USER(`, MariaDB `IDENTIFIED VIA
  ... USING PASSWORD(` and `COPY (` with an unclosed group return an E2002
  error instead of panicking with `index out of range [-1]`. (#872, #880,
  #881)
- **`ExtractColumns` / `ExtractColumnsQualified` no longer report SELECT
  aliases**: an unqualified name in `ORDER BY` or `HAVING` that matches a
  SELECT-list alias of the same query block is treated as the alias, not a
  column. Qualified references stay columns, and aliases never cross
  subquery, CTE or UNION boundaries. This also corrects the MCP
  `extract_metadata` / `analyze_sql` tools. (#865, fixes #849)
- **Extract performance**: `gosqlx.Extract*` and `ExtractMetadata` (and the
  MCP `extract_metadata` / `analyze_sql` tools) took exponential time on nested
  CTEs and UNION chains because CTE, set-operation and DML children were
  visited twice. Each node is now visited once; nested CTEs at depth 10 took
  about 59 s and now finish in microseconds. (#884)
- **AST walkers** (`ast.Inspect`, `Walk`, the security scanner, linter and
  table extraction) reach SELECT `TOP` and ClickHouse `ARRAY JOIN`, the
  ENGINE/ORDER BY/PARTITION BY/TTL/SETTINGS clauses of `CREATE TABLE` and
  `CREATE MATERIALIZED VIEW`, Snowflake `CLONE ... AT`, and PostgreSQL
  partition bounds. `ReleaseAST` returns the pooled nodes under standalone
  `VALUES` statements and top-level set operations. (#867)
- **Transpiler robustness**: very long operator chains (for example 490,000
  `OR` terms) no longer crash the process with an unrecoverable stack
  overflow; the operator and string-literal rewrites walk the tree
  iteratively. (#883)
- **LSP**: a negative `Content-Length` and a `didChange` range past the end
  of the document no longer crash the server; oversized messages are drained
  so framing survives; `didChange` character offsets are read as UTF-16 code
  units and CRLF line ends are respected; a panic in a request handler or in
  background diagnostics is logged and answered with `InternalError` instead
  of ending the process. The document outline no longer lists GO separators,
  and statements before a GO line no longer extend to the end of the file.
  (#867, #882)
- **CLI**: `gosqlx format --dialect sqlserver` runs the statement-count guard
  again, counting GO lines and statements that end without `;`; `lint` no
  longer reports a syntax error twice. (#867, #876)
- **Playground**: copy buttons show their "Copied" state reliably and report
  failures instead of failing silently; the WASM download progress no longer
  exceeds 100%; the Format and Transpile results no longer carry an unused
  `error_span` field. (#888)

### Performance
- **Lower-case formatting** streams into a single builder instead of copying
  and re-rendering subtrees: it went from 3.5–10x to 1.2–1.5x the cost of
  upper-case output, with 5x to 500x fewer allocations. (#870, #886)
- **`ScanSQL` tautology check** no longer allocates per candidate (1 MiB of
  `1=2` went from 50 MB to 1 MB). (#885)
- **`Transpile`** keeps most of its v1.16.0 speed despite the new
  operator-retargeting and `||`-meaning passes: the AST walks follow cached
  per-type reflection plans that skip fields which cannot hold a rewrite
  target, and cheap source checks skip the `||`, string-literal and
  identifier-requoting passes when the SQL cannot need them. Without these,
  the new passes had made a short MySQL `CREATE TABLE` to PostgreSQL take
  5.2 µs; it now takes about 2.7 µs (v1.16.0: 2.0 µs; 43 allocations, v1.16.0:
  32). Wide `OR`/`AND` chains are about 68% faster and `||` chains about 55%
  faster than without the plans. Output and errors are unchanged on 955,476
  differential cases. (#889)
- **Costs of the correctness work** (Apple M4, `-count=6`, against v1.16.0):
  the parse-stage baselines are about 6% slower with 8% fewer allocations and
  about 24% more bytes per parse, from the new AST metadata; all stay within
  the CI regression baselines.

## [1.16.0] - 2026-10-22 — Performance Audit, SQL Highlighting, Dialect-Aware LSP, Claude Code Plugin & ChatGPT App, Correctness Sweep

Covers everything merged since v1.15.0: the October 2026 performance audit
(#566) with large allocation cuts across tokenizer, parser, AST and LSP; the
batch-2/batch-3 correctness sweep (round-tripping `SQL()`, formatter and
`gosqlx format`, render-time injection hardening); new `pkg/highlight` SQL
syntax highlighting across API, CLI, LSP, WASM and playground; a fully
dialect-aware LSP; a hardened `gosqlx-mcp` HTTP server with ChatGPT app support
and a Claude Code plugin; editor-accurate positions (a tab is one column); and
pygosqlx 1.16.0 with dialect support, lint, security scan, transpile and
prebuilt wheels.
The release is source-compatible: exported signatures are unchanged apart from
additions. Runtime behaviour does change (rendered SQL, token positions, error
codes and text, parse acceptance including MySQL `||`, CLI refusals, MCP HTTP
limits), so read **Behavior changes** before upgrading.

### Behavior changes
- **Token positions match editors: a tab is one column and `Start` skips
  comments**: the tokenizer counts a tab as one column (it was four), so
  `a\tb` puts `b` at column 3. The first token after one or more comments, and
  the EOF token after a trailing comment, now start at the token itself rather
  than at the comment. Columns stay 1-based byte offsets. Parse errors, LSP
  diagnostics, semantic tokens, CLI output and the playground move
  accordingly, and error carets repeat the source line's tabs. Consumers that
  mapped columns back to text with tab width 4 must treat them as plain byte
  offsets. `Comment.Start`/`End` are unchanged. (#826, fixes #797)
- **`||` is logical OR under MySQL and MariaDB**: with the `mysql` or `mariadb`
  dialect (API, linter, CLI `--dialect`, LSP), `a = 1 || b` now parses as
  `(a = 1) OR b`, a `BinaryExpression{Operator: "OR", PipesOr: true}`, instead
  of `a = (1 || b)`. `SQL()` and the formatter write `||` back. The linter and
  the security scanner treat it as OR. Pass `parser.WithPipesAsConcat()` /
  `gosqlx.WithPipesAsConcat()` to keep concatenation (`PIPES_AS_CONCAT`).
  Transpiling a `||` concatenation to MySQL/MariaDB now emits `CONCAT(...)`,
  and a MySQL `||` OR becomes `OR` for other targets. Other dialects are
  unchanged. (#790, fixes #781)
- **Composite field access is dialect-gated**: `(expr).field` parses under
  PostgreSQL, BigQuery, `generic` and the default dialect. MySQL, MariaDB, SQL
  Server, SQLite, Oracle, Snowflake, ClickHouse and Redshift return E4001
  ("composite field access ... is not supported in <dialect>"). Array
  subscripts on parenthesized values are not gated. (#843, fixes #839)
- **L006 reports a byte column**: the column-alignment rule reports the 1-based
  byte column of a misaligned column's first character (a tab is one column),
  consistent with token and error positions. Tabs still count as 4 spaces when
  comparing alignment, so which lines are flagged is unchanged. (#840, fixes
  #830)
- **Parenthesized array operands keep their AST grouping**: `(items)[1]` now
  retains a `ParenthesizedExpression` in the subscript's `Array` field. This
  preserves arithmetic precedence and lets `(items)[1].name` round-trip without
  becoming the invalid `items[1].name`. (#834, fixes #833)
- **`gosqlx-mcp` HTTP hardening**: rate limiting now keys on the TCP peer
  address and no longer trusts `X-Forwarded-For` (which let any client evade
  limits and grow limiter memory without bound). Behind a proxy, set
  `GOSQLX_MCP_TRUSTED_PROXY_HEADER` (e.g. `CF-Connecting-IP`, as `render.yaml`
  does) or `GOSQLX_MCP_TRUSTED_PROXY_HOPS`. Limiter memory is capped with
  least-recently-seen eviction; GET (SSE) streams are capped at 4 per client,
  and a GET refused by that cap costs no rate-limit budget; JSON-RPC batches
  are charged per tool call, and a malformed non-empty body or empty batch
  costs 1. Denials are HTTP 429 with `Retry-After` and the request id (a denied
  `initialize`, alone or in a batch, keeps HTTP 200 for mcp-go clients). Oversized bodies (over
  64 KB) get 413, bodies not received within 30s get 408 or a closed
  connection on any route, idle connections close after 120s and headers are
  capped at 32 KB. Bearer tokens are compared in constant time and the
  `Bearer` scheme is case-insensitive. Tool input problems (missing, empty or
  non-string `sql`, parse/format failures, wrongly typed options) are now
  `isError` tool results naming the argument instead of JSON-RPC -32603
  internal errors, and `indent_size` must be an integer from 0 to 16.
  With neither trusted-proxy setting, `gosqlx-mcp` logs a startup warning
  that all clients behind a proxy share one bucket. The opt-in
  `GOSQLX_MCP_TRUSTED_PROXY_SECRET_HEADER`/`GOSQLX_MCP_TRUSTED_PROXY_SECRET`
  pair makes the trusted header and hops apply only to requests that carry the
  shared secret (constant-time compare); other requests are keyed by the peer
  address (see [docs/MCP_GUIDE.md](docs/MCP_GUIDE.md)).
  New `pkg/mcp` API: `NewRateLimitMiddleware(cfg, next)`,
  `Config.TrustedProxyHeader`, `Config.TrustedProxyHops`,
  `Config.TrustedProxySecretHeader`, `Config.TrustedProxySecret`. (#831, #841,
  fixes #838)
- **MCP `format_sql` uppercases more keywords**: `uppercase_keywords: true` now
  also uppercases operator and function keywords (`AND`, `OR`, `COUNT`);
  `indent_size` affects nested blocks only, as now documented. (#823)
- **Comments now count toward `MaxTokens`**: tokens plus collected comments may
  not exceed `MaxTokens` (1,000,000). Past that the tokenizer returns the
  existing E1007 token-limit error at the comment or token that crosses the
  limit. Before, comment-only input was bounded only by `MaxInputSize`; 10 MB of
  `--\n` collected 3.4M comments and peaked at about 960 MB RSS. Pooled
  tokenizers drop a `Comments` slice whose capacity exceeds 1024 entries on
  `Reset`, and
  `ReleaseAST` does the same for `AST.Comments`. (#597, part of #566)
- **`MaxRecursionDepth` (E2007) now covers unary `+`/`-`, `NOT` and derived
  tables**: these three paths recursed outside `parseExpression`, so their
  nesting was limited only by input size. They now share its depth counter and
  `RecursionDepthLimitError` (limit 100): 99 nested unary operators or `NOT`s
  in a select list or `WHERE` parse and 100 return E2007.
  (#597, part of #566)
- **`$name` placeholders keep their text**: `$` followed by a name with no
  closing `$` used to produce a bare `"$"` placeholder and drop the name. It is
  now one placeholder token whose value is `"$name"`, matching `@name` and Oracle
  `:name`. Token counts, types and spans are unchanged, but formatter output and
  fingerprints of such queries change. `$1`, `$$...$$` and `$tag$...$tag$` are
  unaffected. (#597, part of #566)
- **Set-operation chains render in linear time**: the formatter used to copy
  the rendered left side at every level of a left-deep `UNION`/`INTERSECT`/
  `EXCEPT` chain. It now writes the chain once. Output is byte-identical; only
  time and memory change (80,000 `UNION`s: 4.1 s and 46 GB allocated -> 6 ms and
  101 MB). `Format`, `Fingerprint`, `Normalize` and `Transpile` benefit too.
  (#597, part of #566)
- **Token values reference the input (zero-copy)**: identifiers, numbers,
  comments, placeholders, bracket identifiers, dollar-quoted bodies and clean
  quoted literals/identifiers are now substrings of the input rather than
  per-token copies, and so are the AST strings built from them. Keeping any of
  them keeps the whole input string alive, so callers that cache values should
  `strings.Clone` them. `Tokenize([]byte)` copies the input once, so tokens never
  alias the caller's mutable buffer. `ExtractTables`/`ExtractColumns`/
  `ExtractFunctions`/`ExtractMetadata` (and the `Qualified` variants) and
  `schema.LoadFromDDL`/`LoadCatalogFromDDL` clone their result strings so they
  don't pin the input. `Tokenizer.Reset` and `Parser.Reset` now release the
  previous input instead of keeping it reachable from the pool. (#595, fixes
  #546 and #548; #586, fixes #552)
- **Oracle `:1` / `:name` are bind variables**: under `DialectOracle`, `:`
  followed by digits or an identifier is one `TokenTypePlaceholder` (value
  includes the colon). As a consequence, Oracle-mode `arr[1:n]` (not valid
  Oracle) now fails with "expected ], got PLACEHOLDER". Other dialects are
  unchanged. (#595, fixes #520)
- **`INSERT ... WITH ... SELECT` is accepted, and `gosqlx format` keeps leading
  CTEs**: the INSERT error for a missing source now reads "expected VALUES,
  SELECT, or WITH" instead of "expected VALUES or SELECT" (still E2002), and a
  CTE written without `AS` now reports "expected AS, got LPAREN" instead of
  "expected column name". The CLI formatter used to silently drop a leading
  `WITH` on INSERT, UPDATE and DELETE, which changed the statement's meaning;
  it now emits it. (#584, fixes #537)
- **Multi-part names and parenthesized join groups**: column references with
  three or more parts now parse in every dialect. The extra qualifiers are folded
  into `Identifier.Table` as a dotted string (for example `Table: "db.t"`), and
  `Identifier.SQL()` quotes each dotted part separately. More than five parts is
  rejected with E2004. A leading parenthesized join group in FROM is flattened
  into the statement's join chain, so its AST and `SQL()` match the flat query.
  Shapes that flattening would get wrong (a comma list after or inside a group),
  and an alias or ClickHouse `FINAL` after a group, are rejected with E4001.
  `ExtractColumnsQualified` splits a dotted qualifier at its last dot
  (`db.t.col` -> `{Schema: db, Table: t, Name: col}`). (#585, fixes #521)
- **AST visitors see the tree's own nodes**: `Children()`, `Walk` and `Inspect`
  now return pointers into the parent's slices for value-typed children (table
  references, joins, ORDER BY items, WHEN clauses, update assignments, frame
  bounds, MERGE source/target and similar) instead of heap copies. A visitor
  that mutates them now changes the AST, and the change shows in `SQL()` and the
  formatter. These pointers become invalid after `ReleaseAST`. (#588, fixes
  #557)
- **`ReleaseAST` only pools node types the parser draws from pools**:
  `Identifier`, `LiteralValue`, `BinaryExpression`, `FunctionCall`, most other
  expressions and the SELECT/INSERT/UPDATE/DELETE statements are no longer put
  back by `ReleaseAST`/`ReleaseStatements`; they become garbage. The typed
  `Put*` functions keep full semantics for hand-built trees. Nodes returned by
  `Get*` are now fully zeroed, and typed `Put*` wrappers release nested subtrees
  (for example `FunctionCall.Over`/`Filter`) instead of dropping them. (#581,
  fixes #555 and #556)
- **Schema loaders**: the PostgreSQL loader reads `pg_constraint` and now
  requires PostgreSQL 11 or later. Read-only roles now see foreign keys, and
  foreign keys into another schema are reported with the referenced table's bare
  name. Tables with no foreign keys (and MySQL tables with no indexes) carry a
  nil slice instead of an empty one, which serializes as JSON `null`. (#582,
  fixes #579; #570, fixes #565)
- **LSP `Document.Lines` is shared**: `DocumentManager.Get` returns a fresh
  `*Document` header, but its `Lines` now aliases the manager's immutable slice.
  Treat it as read-only. (#573, fixes #564)
- **`gosqlx format` renders through `pkg/formatter` and refuses output that does
  not round-trip**: the CLI's private renderer is gone;
  `cmd/gosqlx/cmd/sql_formatter.go` is now a thin adapter over
  `formatter.FormatStatement`. `SQLFormatter`, `NewSQLFormatter` and `Format`
  keep their signatures, `FormatterOptions` gains a `Dialect` field and
  `AlignColumns` is now ignored. CAST, `::`, EXTRACT, INTERVAL, ANY/ALL, tuples,
  subscripts, ARRAY, ROLLUP/CUBE/GROUPING SETS, WITHIN GROUP, set-operation
  subqueries, ON CONFLICT, RETURNING, PIVOT and ALTER TABLE used to be
  corrupted with exit 0 and now format correctly. Output layout follows
  `pkg/formatter` (CLI separators `;\n\n` / `; `, no trailing semicolon). If the
  formatted text does not re-parse, or re-parses to a different query, the
  command exits non-zero with "formatted output does not re-parse" and
  `format -i` leaves the file untouched. It also refuses output that would drop
  meaningful identifier quotes or change a string literal. With
  `--dialect mysql`/`mariadb` the output must keep exactly the input's
  double-quoted tokens, because MySQL reads `"..."` as a string:
  `WHERE name = "bob"` is refused rather than rewritten as `name = bob`, and
  `` `select` `` rather than rewritten as `"select"`. ANSI_QUOTES-style input
  (`"users"."id"`, `FROM "users"`) is formatted as before. (#599, #624)
- **`Extract*` and `ExtractMetadata` return sorted results; L006/L009 are
  deterministic**: `ExtractTables`, `ExtractTablesQualified`, `ExtractColumns`,
  `ExtractColumnsQualified`, `ExtractFunctions` and `ExtractMetadata` (and the
  MCP `extract_metadata` tool, the cbinding JSON and integrations built on them)
  came out in random map order. Strings now sort in ascending byte order and
  `QualifiedName` values by Schema, then Table, then Name. Costs about 3-15%
  ns/op on the Extract benchmarks; allocs/op are unchanged. L006 now picks the
  earliest continuation-column indent when counts tie, and the text-fallback
  path of L009 lists violations in first-seen table order. Counts, messages and
  lines are unchanged. (#618, #619, #625)
- **`Children()` of `CreateTable`, `FunctionDesc`, `TriggerExecBody` and
  `TriggerReferencing` returns pointers**: `CreateTable.Children()` returns
  `&c.Name`, `&c.Columns[i]` and `&c.Constraints[i]` instead of value copies, so
  type switches on `*ObjectName`, `*ColumnDef`, `*TableConstraint` and
  `*FunctionDesc` match and edits made inside `Inspect` or `Walk` reach the
  parent AST. Visit order is unchanged. (#617, #621)
- **Quoted identifiers that need quotes keep them on render**: `ast.Identifier`
  gains `Quoted`, set for ANSI double-quoted names. `SQL()`, `FormatAST`,
  `Normalize`, `Fingerprint` and `Transpile` output now re-quotes such
  identifiers, and CTE names and column lists, `CREATE [MATERIALIZED] VIEW` names
  and column lists and FROM/JOIN table names that are reserved words or contain
  non-identifier characters. New helpers `ast.QuoteName` and
  `ast.QuoteQualifiedName`. `SELECT "select"` used to render as
  `SELECT select`. A name quoted only for its case (`"Total"`, `"MixedCase"`)
  renders bare, so it keeps matching the alias or column list it refers to;
  the AST does not record quoting for those. Fingerprints of `"id"` and `id`
  are unchanged and still equal; only names that need quotes (such as
  `"select"`) now normalize with them. SQL Server `#temp`, Snowflake
  `@stage/path` and names with Unicode combining marks stay bare. (#611, #632)
- **Smart quotes inside ASCII-quoted tokens are content**: a string or
  identifier opened with `'` or `"` now ends only at the same ASCII quote.
  `“ ” ‘ ’ « »` inside it are kept as written instead of being read as the
  closing quote. Tokens opened with a smart quote keep their previous rules.
  (#632)
- **SQL Server table hints must be bare words**: `WITH (NOLOCK, UPDLOCK)` is
  unchanged, but `WITH (INDEX = ix)` and quoted or bracketed hints are now
  parse errors; they used to be accepted and the hint silently dropped. SQL
  Server now accepts double-quoted constraint names (`CONSTRAINT "x y"`), and
  every dialect accepts `CAST(x AS "type")`. A non-ASCII spelling such as
  `lıke` is stored as `LIKE`; the formatter keeps `WITH` in
  `WITH CHECK OPTION`; and a hand-built `MINUS` set operator renders as the
  equivalent `EXCEPT`. (#604, #632)
- **Readable-style formatting emits one trailing `;`**: with `AddSemicolon`
  (readable style, `FormatString` default) only the outermost statement ends with
  `;`. CTE bodies, `IN`/`EXISTS`/scalar subqueries, set-operation operands and
  the query of `INSERT ... SELECT` / `CREATE VIEW` no longer get an inner `;` or
  `;;`, and a set-operation chain ends with a single `;`. Compact style is
  unchanged. (#602, #631)
- **ClickHouse `SELECT ... SETTINGS ... INTO OUTFILE` is rejected**: the
  SETTINGS clause is now parsed rather than skipped, so the trailing
  `INTO OUTFILE` that used to be swallowed returns a syntax error, matching
  `SELECT ... INTO OUTFILE` elsewhere. Malformed SETTINGS lists and a bare
  `FORMAT` after SETTINGS also return syntax errors; a trailing
  `FORMAT <name>` after SETTINGS is still accepted. (#600, #631)
- **A bare `returning` alias inside an INSERT source or `UPDATE ... FROM` is
  treated as RETURNING**: while parsing an `INSERT` source query or an
  `UPDATE ... FROM` list, an unquoted `returning` is no longer taken as an
  implicit table or select alias. Quoted `returning` and aliases inside nested
  derived tables, `IN`/`EXISTS`, CTE bodies and scalar subqueries are
  unaffected. `RETURNING` is also matched case-insensitively. (#610, #623)
- **Qualified names with more than 5 parts return E2004**: dotted object names
  in FROM, DML targets and DDL (TABLE, VIEW, INDEX, USE and MySQL statements)
  are capped at 5 parts, the limit already applied to column references.
  Every caller (FROM, JOIN, INSERT/UPDATE/DELETE, CREATE, DROP, TRUNCATE,
  REFRESH, SHOW/DESCRIBE/REPLACE, USE, ClickHouse MV `TO`) reports this E2004
  rather than rewrapping it as E2002 "expected table name", and Snowflake's
  permissive `CREATE STAGE/SEQUENCE/FILE FORMAT` path now rejects such names
  instead of keeping a truncated `RawSQL`. Names of 1 to 5 parts render
  byte-identically. (#613, #627)
- **Error context windows are bounded on long lines**: `(*Error).Error()`,
  `FormatMultiLineContext` and `FormatContextWindow` clip source lines over 120
  bytes to about 60 bytes either side of the error column (UTF-8 safe, marked
  with `...`) and cap caret padding. A 100 KB single-line query used to produce
  a 205 KB E1002 string and now produces about 400 bytes. Lines of 120 bytes or
  less render byte-identically. (#615, #626)
- **Pooled tokenizers release oversized `lineStarts`**: `Tokenizer.Reset` keeps
  the backing array only up to 8192 entries (64 KiB) and otherwise replaces it
  with a 16-entry slice, so a pooled tokenizer no longer holds about 72 MB after
  an input with millions of lines. Token output, positions and errors are
  unchanged. (#614, #626)
- **Postgres schema loader reports index columns and key flags correctly**:
  `Index.Columns` is in index key order and excludes INCLUDE columns, which move
  to the new `Index.IncludeColumns`. Expression keys appear as
  `pg_get_indexdef` text instead of being dropped, and indexes on partitioned
  parents are listed. PK/UNIQUE column flags come from `pg_constraint`, so each
  column appears once, `IsUnique` is set only for a single-column UNIQUE and a
  SELECT-only role sees the same schema as the owner. `ForeignKey` gains
  `RefSchema` (empty for MySQL and SQLite). (#620, #622)
- **Named windows round-trip**: `OVER w` now renders as `OVER w` instead of
  `OVER (w)`, and `WINDOW w AS (...)` no longer repeats its name inside the
  parentheses. The non-standard `WINDOW w AS w2` is normalized to
  `WINDOW w AS (w2)`. (#608, #629)
- **LSP semantic token legend changed**: the non-standard `identifier` token
  type is replaced by the standard `variable`, which now covers table, column
  and alias names and quoted identifiers (double-quoted identifiers were
  `string` before). Function names are `function` and type names are `type`.
  Comments and placeholders (`$1`, `?`, `:name`, `@var`) are now emitted, as
  `comment` and `parameter`. AND, OR and NOT stay `keyword`. Positions are
  UTF-16 code units. Clients with custom rules keyed on the old `identifier`
  type (for example Neovim `@lsp.type.identifier` highlight links) must switch
  to `variable`. (#825)
- **pygosqlx requires Python 3.10 or later**: 3.8 and 3.9 are dropped, and
  the package metadata lives only in `pyproject.toml` (`setup.py` is a shim
  that tags platform wheels). (#851)

### Added
- **Claude Code plugin and marketplace**: `/plugin marketplace add
  ajitpratap0/GoSQLX` then `/plugin install gosqlx@gosqlx` installs the
  `gosqlx` plugin (`plugins/gosqlx/`): the hosted MCP server, five SQL skills
  (analysis, formatting, security review, linting, dialects), four slash
  commands, a read-only `sql-reviewer` agent and an opt-out PostToolUse hook
  that validates edited `.sql` files when the `gosqlx` CLI is installed.
  (#823)
- **ChatGPT app support in `gosqlx-mcp`** (OpenAI Apps SDK and MCP Apps):
  `analyze_sql` links an embedded report widget
  (`ui://gosqlx/analysis-v1.html`, `text/html;profile=mcp-app`); all tools now
  return `structuredContent` alongside the unchanged text JSON, carry
  `securitySchemes`/invocation-status metadata, and the server sends usage
  instructions. The server reports `gosqlx.Version`; `/health` reports the real tool count; the
  optional `GOSQLX_MCP_OPENAI_APPS_CHALLENGE` env var serves
  `/.well-known/openai-apps-challenge` for app verification; idle MCP sessions
  have their transport state swept 30–45 minutes after their last request
  (`SessionIdleTTL`, sweep every TTL/2) instead of living until restart, and
  session IDs are generated statelessly and redacted from transport error logs
  (#835). `Server.Shutdown(ctx)` stops the transport, and `Server.Start`
  sets read-header and idle timeouts. The `analyze_sql` widget caps long
  lists, shows failed calls as errors and avoids blocked clipboard calls. Setup:
  `integrations/chatgpt/README.md`, details: `docs/CHATGPT_APP.md`. (#823;
  #831, #835)
- **SQL syntax highlighting (`pkg/highlight`)**: `highlight.Spans(sql, opts...)`
  classifies SQL into sorted, non-overlapping byte-offset spans tagged with one
  of 13 stable categories (keyword, function, type, identifier,
  quoted-identifier, string, number, constant, operator, punctuation, comment,
  placeholder, error). It is dialect-aware via `WithDialect`, never fails
  (input after the first lexical error becomes one `error` span), and detects
  functions in call position and types in type position. Renderers: `ANSI` /
  `WriteANSI` (256-color, true color or attributes only), `HTML` / `WriteHTML`
  (classes or inline styles) and `CSS`, with `dark`, `light` and `mono` themes.
  Spans marshal to JSON. Built on top of it:
  - `gosqlx.Highlight`, `gosqlx.HighlightANSI` and `gosqlx.HighlightHTML`.
  - `gosqlx highlight [file|SQL]` (alias `hl`, reads stdin) with
    `--format ansi|html|json|css`, `--theme`, `--dialect`,
    `--color auto|always|never` (honors TTY, `NO_COLOR` and `COLORTERM`) and
    `--standalone` for a full HTML page.
  - LSP `textDocument/semanticTokens/full` uses `pkg/highlight` (see Behavior
    changes), with per-line splitting of multi-line tokens and coverage of
    every dialect keyword and all comments.
  - WASM `gosqlxHighlight(sql[, dialect])` returns spans with UTF-16 offsets;
    the gosqlx.dev playground uses it for editor highlighting.

  See [docs/HIGHLIGHTING.md](docs/HIGHLIGHTING.md). (#825; #836)
- **Dialect-aware LSP server**: the dialect from `initializationOptions.dialect`
  now drives every feature, not only semantic tokens. Diagnostics, formatting
  and document symbols tokenize and parse with the dialect's rules (MySQL
  `LIMIT 5, 10` is valid under `mysql`, `ILIKE` is reported under `mysql`);
  completion and hover add the dialect's own keywords. The server also handles
  `workspace/didChangeConfiguration` with `{"gosqlx": {"dialect": "..."}}`:
  it switches dialect without a restart, re-publishes diagnostics for open
  documents and, when the client advertises `refreshSupport`, sends
  `workspace/semanticTokens/refresh`. Invalid values fall back to `generic`, as
  in `initialize`. The default `generic` dialect keeps the previous behaviour
  for every feature. See [docs/LSP_GUIDE.md](docs/LSP_GUIDE.md#sql-dialect).
  (#828)
- **`--dialect` flag for the `parse`, `format`, `analyze`, and `lint` CLI
  commands**: dialect-specific SQL (e.g. MySQL `LIMIT offset, count`) can now be
  parsed by these commands, matching the existing `validate --dialect`. Unknown
  dialect names are rejected up front. The default remains PostgreSQL.
  `pkg/linter.Linter` gains a `SetDialect(keywords.SQLDialect)` method so the
  linter can tokenize/parse dialect-specific syntax, and `lint --security` now
  parses with the selected dialect. (#526)
- **`?` positional placeholders for MySQL, MariaDB and SQLite**: under these
  dialects a bare `?` is now a `TokenTypePlaceholder` (the bind parameter used
  by their `database/sql` drivers) instead of the PostgreSQL JSON key-existence
  operator. PostgreSQL and the other dialects keep `?`/`?|`/`?&` as JSON
  operators, and the default dialect is unchanged. (#527, fixes #522)
- **Oracle bind variables**: `:1`, `:10`, `:name` and `:new_a` parse under
  `DialectOracle` and round-trip byte-for-byte through `SQL()` and the
  formatter. Previously `WHERE id = :1` failed with "unexpected token: COLON".
  (#595, fixes #520)
- **`Tokenizer.TokenizeString(s string)` and
  `Tokenizer.TokenizeStringContext(ctx, s string)`**: tokenize a string in place
  without the `[]byte` round trip. Both return `[]models.TokenWithSpan`; token
  values reference `s`. (#595, fixes #546)
- **ClickHouse `SAMPLE` and `ORDER BY ... WITH FILL` round-trip**: `SAMPLE` now
  renders, and `WITH FILL [FROM x] [TO y] [STEP z]` is stored in the new
  `WithFillClause` instead of being skipped. (#534)
- **ClickHouse tuple/array element access with a dot** (`d.1`, `tuple.2`).
  (#535)
- **`JOIN ... USING (cols)` is kept**: stored in the new `JoinClause.Using`
  (one `*ast.Identifier` per column, `Condition` left nil) and rendered as
  `USING (c1, c2)` by `SQL()`, `pkg/formatter` and `gosqlx format`, instead of
  `ON cols`. `Children()`, `Walk` and `ReleaseAST` cover the columns, and the
  schema validator checks each one. (#603, #630)
- **Parenthesized set operations**: a derived table in FROM, JOIN or a comma
  list can be a set operation, a `WITH` query or a doubly parenthesized query,
  and a statement or set-operation operand can be written as `(query)`, e.g.
  `(SELECT 1) UNION (SELECT 2)`. New `TableReference.SetSubquery` and
  `SetOperation.LeftParenthesized` / `RightParenthesized`; parentheses that
  change meaning (`A EXCEPT (B UNION C)`) are kept on render. ORDER BY/LIMIT the
  AST cannot represent returns E4001. (#612, #630)
- **Window frame `GROUPS` unit, `EXCLUDE` clause, named-window refinement and
  `INTERVAL` qualifiers**: `GROUPS` frames and `EXCLUDE CURRENT ROW | GROUP |
  TIES | NO OTHERS` (new `WindowFrame.Exclude`) parse and render;
  `OVER (w ORDER BY z)` refines an existing window via the new
  `WindowSpec.BaseWindow`; `INTERVAL '1' DAY` and `INTERVAL '1-2' YEAR TO MONTH`
  parse into the new `IntervalExpression.Qualifier`, which fixes
  `d + INTERVAL '1' DAY` rendering as `INTERVAL '1' AS DAY`. `GROUPS` and
  `EXCLUDE` are not gated by dialect. (#608, #609, #629)
- **INSERT forms**: `RETURNING` after `INSERT ... SELECT`, `INSERT ... DEFAULT
  VALUES` (new `InsertStatement.DefaultValues`), MySQL/MariaDB `INSERT ... SET`
  (new `InsertStatement.SetSyntax`), parenthesized query sources
  (`INSERT INTO t (SELECT ...)`) and `UPDATE ... FROM` with a comma-separated
  table list. `SQL()` and `FormatAST` render `DEFAULT VALUES` and the SET form;
  `UPDATE ... FROM ... JOIN` returns E4001. (#610, #623)
- **ClickHouse table functions and parametric aggregates**: `numbers(10)`,
  `remote(...)`, `file`, `s3`, `cluster`, `generateRandom` and the
  keyword-named `url`, `merge`, `values` and `null` parse in FROM as a
  `TableReference` with `TableFunc`. `quantile(0.5)(DISTINCT x)` keeps DISTINCT
  with the argument group; DISTINCT or ORDER BY in the parameter group and a
  third paren group return E2004. A `[...]` subscript or slice directly after a
  function call (`groupArray(x)[1]`, `array_agg(x)[1]`) parses as
  `ArraySubscriptExpression` / `ArraySliceExpression`; SQL Server keeps
  `count(*) [cnt]` as an alias, and SQLite behaves as before. (#605, #606,
  #628)
- **ClickHouse `SELECT ... SETTINGS` is kept**: parsed into the new
  `SelectStatement.Settings` (`[]ast.QuerySetting`, stored on the rightmost
  SELECT of a set operation) and rendered by `SQL()` and `pkg/formatter`.
  (#600, #631)
- **Rendering of `IGNORE NULLS`, named arguments, `ON DUPLICATE KEY UPDATE` and
  `INSERT ... OUTPUT`**: `SQL()` and `pkg/formatter` (compact and readable) used
  to drop these; they now render, with `name => value` via the new
  `(*ast.NamedArgument).SQL()`. (#600, #631)
- **SQL Server table hints and PIVOT rendering**: `SQL()` renders
  `WITH (NOLOCK)`-style hints and `PIVOT`/`UNPIVOT` with the alias as
  `AS alias` (`FROM s PIVOT (...) AS p` used to render as `FROM s p`), and
  `pkg/formatter` renders hints. (#604, #632)
- **`ALTER TABLE` rendering in `pkg/formatter`**: `FormatStatement` and
  `FormatAST` render ALTER TABLE operations (ADD/DROP COLUMN, RENAME,
  ADD/DROP CONSTRAINT, ALTER COLUMN ...) instead of the bare token `ALTER`.
  (#599, #624)
- **New schema fields**: `db.Index.IncludeColumns` and `db.ForeignKey.RefSchema`
  (see Behavior changes). (#620, #622)
- **`ast.FieldAccessExpression`**: represents composite-field selection with a
  traversable base expression, field name, quote flag and source position.
  (#834, fixes #833)
- **Table-function column alias lists and `WITH ORDINALITY`**: FROM and JOIN
  table functions accept `AS g(a, b)`, and PostgreSQL also accepts
  `WITH ORDINALITY` with or without an alias list
  (`unnest(arr) WITH ORDINALITY AS t(elem, n)`). They are exposed as
  `ast.TableReference.ColumnAliases` (`*ast.ColumnAliasList`) and
  `TableReference.WithOrdinality`, plus the new
  `dialect.Capabilities.SupportsCompositeFieldAccess`. `SQL()` and the
  formatter round-trip them. (#843, fixes #839)
- **`WithPipesAsConcat` options, `ast.BinaryExpression.PipesOr` and
  `dialect.Capabilities.PipesAsLogicalOr`** (see Behavior changes). (#790)
- **`gosqlx.LintWithDialect(sql, dialect)`**: runs the full built-in rule set
  with a per-dialect cached linter, so AST rules also run on SQL that parses
  only in that dialect. Unknown dialects return `ErrUnsupportedDialect`. (#780)
- **pygosqlx 1.16.0: dialects, lint, security scan and transpile**: `parse`,
  `validate`, `validate_detailed`, `format` and the `extract_*` functions take
  an optional `dialect=` argument (for example `dialect="sqlserver"`), and
  `pygosqlx.dialects()` lists the supported names. An unknown dialect raises
  `UnsupportedDialectError`, which is also a `ValueError`. New
  `pygosqlx.lint()` runs the `gosqlx lint` rule set (L001-L010, optional
  `dialect=` and `max_line_length=`), `pygosqlx.security_scan()` returns typed
  SQL injection findings with severity counts, and
  `pygosqlx.transpile(sql, from_dialect, to_dialect)` converts SQL between
  dialects. libgosqlx gains the `gosqlx_*_dialect` variants and
  `gosqlx_lint`, `gosqlx_security_scan`, `gosqlx_transpile` and
  `gosqlx_dialects`; each returns a JSON string the caller frees with
  `gosqlx_free`. The existing exports are unchanged. `transpile()` raises the
  new `TranspileError` when SQL cannot be parsed or rewritten, and results
  come back as the `LintResult`/`LintViolation` and
  `SecurityScanResult`/`SecurityFinding` dataclasses. (#850)
- **pygosqlx prebuilt wheels and PyPI release pipeline**: wheels bundle the
  native library for Linux x86_64/aarch64 (`manylinux_2_17`), macOS
  x86_64/arm64 (13+) and Windows AMD64, and are tested on Python 3.10-3.14.
  pygosqlx is now versioned in lockstep with GoSQLX (it was 0.2.0), and each
  GoSQLX release tag publishes the matching version to PyPI through Trusted
  Publishing (`.github/workflows/pygosqlx-release.yml`), starting with
  `pip install pygosqlx==1.16.0`.
  On a platform with no prebuilt wheel, installing from the sdist now fails
  with an error unless the native library has been built first, instead of
  installing a package that cannot load; set `PYGOSQLX_ALLOW_MISSING_LIB=1`
  to install anyway and supply `GOSQLX_LIB_PATH` at runtime. (#851, #852)
- **`rules.CoreRules` / `rules.DefaultCoreConfig`** (new package
  `pkg/linter/rules`): the core L001-L010 rule set, defined once and shared by
  `gosqlx lint`, `gosqlx action`, the MCP `lint_sql` tool, the C binding's
  `gosqlx_lint` and `gosqlx.Lint`. Each keeps its existing settings and
  output; `CoreConfig` covers the L003, L004 and L005 limits. (#853)

### Changed
- **`tokenizer.NewWithKeywords` no longer consults its keyword table**: the
  tokenizer's keyword field was never read, so it was removed. `NewWithKeywords`
  keeps its signature and nil check. `keywords.Conflicts()` now reflects only
  explicit `keywords.New` calls, because parsing no longer calls it. (#595,
  fixes #550)

### Fixed
- **PostgreSQL composite-returning function queries parse correctly**:
  `(get_item(payload)).name` and `(get_item(payload)).*` retain their base
  expression in a new `ast.FieldAccessExpression`, including quoted field names
  and chained field/subscript access. SQL rendering, AST traversal, extraction,
  security scanning and expression release preserve the nested expression.
  Direct `JOIN LATERAL get_item(t.payload) AS f` references now parse their
  arguments under the same dialect gate as FROM table functions. Any keyword,
  reserved ones included, can follow the dot (`(a).order`, `(f(x)).from`), as
  in PostgreSQL, and renders unquoted. Composite access is dialect-gated (see
  Behavior changes). (#834, fixes #833; #843, fixes #839)
- **Arithmetic and `||` on the right of a comparison or LIKE/ILIKE/REGEXP
  pattern parse**: `WHERE a = 1 + 2` failed with "expected statement, got
  PLUS". Comparisons still do not chain. (#734, fixes #596)
- **Pooled and zero-value parsers report the default capabilities**:
  `GetParser().Capabilities()` and a literal `&parser.Parser{}` returned
  all-false capabilities instead of matching `NewParser()`. (#735, fixes #590;
  #789, fixes #784)
- **Oracle `CONNECT BY` accepts general expressions**: `PRIOR` is a prefix
  operator, so `CONNECT BY PRIOR id = parent_id + 1` parses. A column named
  `prior` is still an identifier. (#791, fixes #783)
- **Snowflake `VariantPath` renders**: `WHERE src:a = 1` came out as
  `WHERE : = 1` from `SQL()` and the formatter. Keys that are not bare words
  are double-quoted. (#786, fixes #782)
- **Lower- and mixed-case `CROSS JOIN`, `FULL JOIN` and `GROUPING SETS`
  parse**, so formatter output with lower-case keywords round-trips. (#844,
  fixes #842)
- **Playground Lint and Analyze**: Lint runs all 30 rules (it ran 3, and the
  tab always reported clean SQL), Analyze reports a parse error instead of
  scoring unparseable SQL, security findings and optimization suggestions are
  listed, and the editor marks parse errors. (#780, fixes #737, #738, #739,
  #758; #796)
- **`gosqlx.Version` and `gosqlx --version` report the release version**:
  v1.15.0 still reported 1.14.0, and so did the MCP server info and `/health`.
- **`gosqlx_version()` double free in the C binding**: it returned a cached,
  process-wide pointer although the binding documents every result as
  caller-owned, so the second `pygosqlx.version()` call in a process freed it
  again and aborted with "pointer being freed was not allocated". It now
  returns a fresh string on every call; free it with `gosqlx_free`.
  `pygosqlx.__version__` reports the packaged version, and editable installs
  work with current setuptools. (#847)
- **LSP `serverInfo.version` and release binaries report the real version**:
  the LSP server reported a hard-coded `1.0.0` in `serverInfo.version` and now
  reports the library version. The `gosqlx` binary bundled with the VS Code
  extension prints the release tag from `gosqlx --version`; set the CLI
  version at build time with
  `-ldflags "-X github.com/ajitpratap0/GoSQLX/cmd/gosqlx/cmd.Version=<version>"`.
  GoReleaser no longer passes a `-X main.version` flag that the example
  binaries ignored. (#846) An unstamped CLI now reports `gosqlx.Version`, so
  the CLI and library versions cannot drift, and `release.yml` fails a tag
  that does not match `gosqlx.Version`. (#853)
- **Tokenizer pool no longer leaks dialect state**: a tokenizer whose dialect was
  changed via `SetDialect` (e.g. by `validate --dialect mysql`) is now restored to
  the default (PostgreSQL) dialect when returned to the pool via `PutTokenizer`.
  Previously `Reset` did not clear the dialect/keywords, so a later
  `GetTokenizer` caller could receive a tokenizer configured for the wrong
  dialect and silently mis-parse. The restore lives in `PutTokenizer` (the pool
  boundary), not `Reset`, because `Reset` also runs at the start of every
  `Tokenize` call where the configured dialect must persist. The keyword table is
  rebuilt only when a non-default dialect was configured, so the common path is
  unaffected. (#525)
- **Parentheses in expressions are preserved**: `(a = 1 OR b = 2) AND c = 3`
  used to re-render as `a = 1 OR b = 2 AND c = 3`, which changed the predicate.
  The parser now keeps grouping in a new `ast.ParenthesizedExpression` node.
  (#532, fixes #519)
- **`IS NOT NULL` no longer renders as `IS NULL`**, and ClickHouse parametric
  aggregates keep their parameter group in `SQL()`
  (`quantileTDigest(0.95)(value)` stayed `quantileTDigest(value)`). (#529,
  fixes #530; AST half of #531)
- **`gosqlx format` keeps ClickHouse parametric aggregate parameters**: the CLI
  renderer also dropped the `(params)` group. (#583, fixes #531)
- **`gosqlx format` no longer panics on `NOT EXISTS (subquery)`**. (#591, fixes
  #587)
- **Numeric window-frame offsets are kept**: `ROWS BETWEEN 1 PRECEDING AND
  CURRENT ROW` rendered as `ROWS BETWEEN PRECEDING AND CURRENT ROW` in `SQL()`,
  `pkg/formatter` and the CLI. The CLI also stopped adding `BETWEEN` to a
  single-bound frame. (#592, fixes #589)
- **`INSERT INTO t (cols) WITH c AS (...) SELECT ...` parses** in every
  dialect (it failed with E2002 "expected VALUES or SELECT, got WITH"). A `WITH`
  is also no longer dropped from a CTE query whose body is a chain of two or more
  set operations. (#584, fixes #537)
- **MySQL three-part identifiers and parenthesized join groups parse**: SHOW
  CREATE VIEW output such as `` `sakila`.`city`.`city` `` and `FROM ((a JOIN b
  ON ...) JOIN c ON ...)` is accepted. (#585, fixes #521)
- **Schema loaders**: PostgreSQL composite foreign keys are no longer
  cross-multiplied, same-named constraints on different tables stay separate,
  partition clone constraints are skipped, and quoted index column names decode
  exactly. The MySQL foreign-key join also matches on table name. (#582, fixes
  #579)
- **Schema loaders no longer deadlock or return empty tables**: a `*sql.DB` with
  `MaxOpenConns=1` used to deadlock and a pooled SQLite `:memory:` database
  returned tables with no columns, because cursors were nested. SQLite table
  names are passed as bound parameters, so names containing quotes or
  backslashes load, and PostgreSQL PK/UNIQUE flags no longer leak between
  tables that share a column name. (#570, fixes #565)
- **AST release-path defects**: `PutSelectStatement` no longer releases a
  derived-table subquery twice through `Joins[i].Left`, which could make two
  later `GetSelectStatement` calls return the same object. Pooled expression
  nodes no longer carry stale fields. (#581, fixes #555)
- **Long comment runs no longer grow the stack**: the tokenizer skips
  consecutive comments in a loop instead of recursing once per comment. (#597)
- **`NOT EXISTS (subquery)` rendered as `NOT (EXISTS (...) NOT )`**, which failed
  to re-parse with E2002. `SQL()`, `FormatAST` and `FormatString` now render
  `NOT EXISTS (...)`; the AST shape is unchanged. (#601, #632)
- **Table-function arguments in FROM were dropped on render**:
  `generate_series(1,10) AS g` came out as `generate_series g`. `SQL()` and
  `pkg/formatter` now render the call for PostgreSQL, Snowflake, BigQuery and
  ClickHouse table functions, and `transform.ReplaceTable` renames
  table-function references. (#607, #628)
- **Bogus context in 15 parser errors**: nine E2002 and six E2004 sites passed
  an explanatory sentence as the SQL source, so `Error()` printed it as line 1
  of the user's query. The context is now empty and the sentence is the
  error's `Hint`; code, message and position are unchanged. The BETWEEN, LIKE,
  REGEXP and IN-subquery operand wrappers likewise stop printing a fake
  `1 | )` snippet and keep the inner error as `Cause`. (#616, #627)
- **`gosqlx format` dropped or mangled constructs** (see Behavior changes):
  `JOIN ... USING` printed `ON LIST`, and WINDOW, INTERVAL, `UPDATE ... FROM` and
  `DEFAULT VALUES` were lost. (#599, #603, #608, #609, #610, #624)
- **Readable-style output that did not re-parse**: inner `;` and `;;` removed
  (#602, #631); readable-style re-parse failures over the testdata corpus fell
  from 36 to 6.
- **Tokenizer error locations point at the offending construct**: an
  unterminated dollar-quoted string (`$$`/`$tag$`) and an unterminated SQL
  Server `[identifier]` now report their opening delimiter instead of the end of
  input, and a double-quoted identifier broken by a newline now reports its
  opening quote on the correct column. These errors, invalid escape sequences
  (which point at the character after the backslash) and `StringLiteralReader`
  errors now use the same rule as token spans: 1-based line, 1-based byte
  column, a tab counting as one column. Before, they used internal rune counts,
  so the column drifted after multibyte characters and could be 0, and a dollar
  quote could report the wrong line. The two errors with no position
  (`keywords cannot be nil`, input too large) report column 1 instead of 0.
  Error codes and messages are unchanged. (#827, follows #826)
- **Dialect lists now agree everywhere**: the `--dialect` help on `parse`,
  `format`, `analyze`, `lint` and `validate`, the CLI's unknown-dialect error,
  config-file validation, the MCP `validate_sql` schema, the playground WASM
  bridge, the GitHub Action and the VS Code `gosqlx.dialect` setting all list or
  accept the same 11 names: `generic`, `postgresql`, `mysql`, `mariadb`,
  `sqlserver`, `oracle`, `sqlite`, `snowflake`, `bigquery`, `redshift`,
  `clickhouse`. Before, help listed 7, the error omitted `generic` and
  `clickhouse`, `pkg/config` rejected `generic`, `bigquery`, `redshift` and
  `clickhouse`, and the VS Code setting offered 6 (and suggested `mysql` for
  `mariadb`). The Go lists derive from the new `keywords.DialectNames()`, and a
  test checks the VS Code extension and the example configs and READMEs against
  it. Names stay case-sensitive in the CLI. `transpile --from/--to` keep their
  own list of transpilable dialects. (#829)

### Performance
Numbers are quoted from each PR (benchstat on an Apple M4 unless stated; the
#597 figures are single before/after measurements).
- **Linear tokenizer position tracking**: line/column lookup no longer rescans
  from the start of the line for every token, which made long single-line input
  quadratic. `LargeSQL_100KB` 20.6 ms -> 1.96 ms, `VeryLargeSQL_1MB` 1755 ms ->
  21.8 ms, `LargeInClause` 4.87 ms -> 136 us; allocs/op unchanged. Also adds
  ASCII fast paths for keyword and identifier scanning and a counted token-slice
  capacity. (#577, fixes #544, #545, #547, #549)
- **Zero-copy token values**: tokenizer allocs/op drop 88-93%
  (`Tokenizer/ComplexSQL` 120 -> 14, `MediumSQL_10KB` 2823 -> 203,
  `LargeSQL_100KB` 28139 -> 1988) and gosqlx parse allocs/op drop 37-66%
  (`Parse_ComplexQuery` 193 -> 74). B/op rises 1-6% on the tokenizer, and
  `Tokenize_SimpleQuery` on the `[]byte` path is about 3% (11 ns) slower. (#595,
  fixes #546)
- **Escape-free quoted literals are substrings**: quote-heavy inputs go from
  400+ to 2 allocs/op and run 31-56% faster; `TokenizeString/ComplexSQL` 13 -> 5
  allocs/op. The unused global buffer pool is gone. (#595, fixes #548)
- **Dialect-aware entry points use the pools**: `ParseBytesWithDialect`
  21.8 us / 70 allocs -> 4.06 us / 28 allocs (the same as `ParseBytes`),
  `ParseTree` with a dialect 22.0 us -> 1.25 us, `SetDialect` 35.6 us / 76
  allocs -> 0 allocs, `transpiler.Transpile` 20.2 us -> 1.69 us and
  `transform.ParseSQLWithDialect` 35.9 us -> 0.84 us. (#595, fixes #550)
- **Allocation-free parser preprocessing**: keyword classification and
  compound-token expansion no longer allocate. Parser allocs/op drop 20-50%
  (`SimpleSelect_1000_Columns` 2020 -> 1018, `SELECT_Complex` 198 -> 114), and
  qualified identifiers and clause parsing lose an allocation each. (#578, fixes
  #551, #553, #554)
- **Parser-owned preprocess buffer**: `ParserSimpleSelect` 9 -> 7 allocs/op and
  1696 -> 816 B/op, `ParserComplexSelect` 22 -> 20 allocs/op (-64% B/op).
  (#586, fixes #552)
- **Writer-based `SQL()` serialization**: a statement renders into one pooled
  buffer. `BenchmarkSQL/7line` 57 -> 1 allocs/op and `15line` 122 -> 1, about
  3x faster; output is byte-identical. (#575, fixes #558)
- **`Children()` stops heap-copying nodes**: `Inspect` 47 -> 26 allocs/op and
  3216 -> 928 B/op, `Lint/Realistic` 728 -> 580 allocs/op, `Extract*` 20-45%
  fewer allocations. (#588, fixes #557)
- **Cheap `PutExpression` after large lists**: the work queue is cleared only to
  its high-water mark. `PutLeafAfterBigList` 2995 ns -> 19 ns. (#581, fixes
  #555)
- **`ExtractMetadata` in one AST pass**: 114 -> 24 allocs/op, 8264 -> 2208 B/op,
  about 2.4-2.8x faster. (#572, fixes #561)
- **`SplitStatements` slices the source**: 855 -> 1 allocs/op, 49.3 -> 6.4 KiB/op
  and 32-41% faster on a 200-statement script. (#569, fixes #559)
- **`gosqlx.Lint` builds its rule set once**: `Lint/Tiny` 169 -> 137 allocs/op.
  L015 no longer upper-cases the whole input (1 -> 0 allocs/op, 96 KiB -> 0 B on
  ~100 KB of SQL). (#568, fixes #562)
- **AST and parser release in batch helpers**: `ValidateMultiple`,
  `ParseMultiple` (error paths), `Analyze`, `Transpile` and the `transform` parse
  helpers return ASTs and parsers to their pools, so pool Get/Put counts balance.
  (#571, fixes #560)
- **`ScanSQL` literal prefilters**: regexes whose required literals are absent
  are skipped. `ScanSQL` 26.9 us -> 4.7 us (-82%) and malicious-input benchmarks
  56-90% faster, with identical findings. (#574, fixes #563)
- **LSP splits each document once per request**: `BuildDiagnostics` on 10,000
  lines 789 MiB / 512 ms -> 1.2 MiB / 6.8 ms, `Hover` 5296 B / 9 allocs -> 368 B
  / 5 allocs, `SignatureHelp` 3535 B / 50 allocs -> 224 B / 4 allocs, and
  `sendMessage` writes each frame once (11 -> 7 allocs). (#573, fixes #564)
- **Schema loaders batch their queries**: `Load` runs 4 statements instead of
  3N+1. SQLite at 100 tables: 16.7K -> 9.9K allocs/op, 679 -> 250 KiB/op,
  3.59 -> 1.92 ms. (#570, fixes #565)
- **Linear inline-comment detection**: 1 MiB of spaces followed by 20,000
  comments tokenizes in 9.8 ms instead of 10.3 s. (#597)
- **Performance baselines refreshed**: `performance_baselines.json` re-measured
  on 2026-10-13. Baselines are now about 2.5x the Apple M4 median, because
  GitHub's ubuntu-latest runners measure about 1.5-3.2x slower than M4 on these
  queries (up to ~3.2x), so a 1.5x baseline would fail CI's slowest runs. (#566)
- **Qualified-name parsing is linear**: `parseQualifiedName` collects up to 5
  parts in a stack array and joins them once instead of concatenating per part.
  A 64 KB `a.a.a...` chain went from 66 ms and 1.17 GB (and parsed) to 8 ms and
  10.5 MB (E2004); `allocs/op` on 3- and 5-part names fell 10% and 25%. (#613,
  #627)
- **Long error lines are cheap to render**: error context uses a bounded line
  scan. Long-line `Error()` went from 49 us / 937 KiB to 1.4 us / 1.3 KiB per
  op, and the context-format benchmarks are about 20% faster. (#615, #626)
- **Measured costs of batch-3 correctness fixes**: `ast.Identifier` grows from
  48 to 64 bytes for the `Quoted` flag, raising parser B/op by about 4-6%, and
  rendering with name quoting makes `SQL()` about 8% slower with unchanged
  allocations (#611, #632). `TableReference` grows from 128 to 136 bytes for
  parenthesized set operations: `BenchmarkParserSimpleSelect` +4.8% and
  +16 B/op (#612, #630). Reallocating `lineStarts` per call on very large
  inputs adds about 2.4% B/op above roughly 410 KB (#614, #626). Sorted
  `Extract*` results cost 3-15% ns/op on the Extract benchmarks (#618, #625).

### Security
- **Render-time SQL injection closed**: quoted names and some literal and
  keyword values were written into rendered SQL verbatim, so
  `SELECT 1 AS "a; DROP TABLE x; --" FROM t` came back from `gosqlx.Format`,
  `SQL()`, `Normalize` or `Transpile` as two statements. Every name position
  (SELECT, table, derived-table, JOIN, PIVOT, UPDATE/DELETE and MERGE aliases,
  window names, DML targets and column lists, DDL names, constraint and
  function names, data types) is now quoted when it is not a plain
  identifier or is reserved. INTERVAL, PRAGMA, table-hint and PIVOT values are
  escaped, and the formatter's `-- UNSUPPORTED:` comment covers every line.
  Keyword fields (join type, set operator, DROP object type, interval unit,
  constraint, partition, ALTER, MERGE, frame and lock types, FK actions,
  FETCH, SAMPLE, table options, view `WITH` option, SHOW kind) are checked
  against exact allow-lists; a hand-built value outside its list is dropped
  or rendered so that the output fails to parse, never as an extra statement.
  Found by the batch-3 adversarial review and validated with hostile-name and
  AST-mutation fuzzing across all dialects. (#632)
- **Bounded input-driven work**: comment counts, nesting depth for unary
  operators, `NOT` and derived tables, comment runs and set-operation rendering
  are now bounded or linear (see **Behavior changes**). These were found by the
  pre-merge security review. (#597)
- **Tokenizer CPU-DoS on long single lines fixed** by linear position tracking.
  (#577, fixes #544)
- **Code-scanning and Dependabot alerts**: every GitHub Actions `uses:` is pinned
  to a commit SHA, workflows default to read-only permissions, install commands
  use pinned versions or lockfiles, blog slugs are validated (3 XSS alerts),
  Docker base images are pinned by digest, and OpenTelemetry v1.47.0,
  `filippo.io/edwards25519` v1.1.1 and `golang.org/x/sys` v0.49.0 are picked up.
  (#567)
- **Scanner descends into table-function arguments**: `url(...)`, `file(...)`
  and similar ClickHouse table functions are detected as out-of-band access
  (also via a `FROM|JOIN <fn>(` pattern), and the scanner descends into array
  subscripts and slices so `pg_sleep(5)[1]` is not a bypass. The check is
  dialect-agnostic by design. (#605, #607, #628)
- **Scanner walks nested set-operation trees**: `checkUnionInjection` handles
  right-nested and parenthesized `UNION`/`EXCEPT` trees, so
  `x UNION (SELECT ... FROM pg_user UNION ...)` is no longer missed after
  parenthesized set operations became parseable. (#612, #630)
- **ANSI highlighting neutralizes terminal control characters**: an ESC or
  other control character inside a string literal or comment could inject
  OSC/CSI sequences when highlighting untrusted SQL. C0 controls other than
  tab/LF/CR are shown as Unicode control pictures (ESC becomes U+241B), DEL as
  U+2421, and C1 controls and invalid UTF-8 as U+FFFD. HTML output was already
  escaped. (#836)
- **`gosqlx-mcp` no longer logs session IDs**: transport error paths reachable
  by an unauthenticated response-shaped POST logged the client-supplied
  `Mcp-Session-Id`. Non-allowlisted error arguments are now redacted and
  generated IDs scrubbed, and the stateless session-ID manager is pinned so
  terminated IDs are never retained. (#835)
- Dependency patches: certifi 2026.10.19 (CI Sentry script) and markdown-it
  14.3.3 (VS Code extension). (#837)

### Internal
- CI: claude-code-action v1, fork-PR review skip, Scorecard v2.4.4 and a valid
  glama-sync workflow (#536, #538, #539, #540); `.gitattributes` enforcing LF
  line endings for golden fixtures (#594).
- Website and playground: the playground WASM is built during deployment,
  revalidated by browsers and no longer committed (#543, #580).
- Docs: the CHANGELOG restored after the #526 merge emptied it (#593).
- Website and docs: gosqlx.dev redesign (design tokens, light-mode parity,
  type scale, home, docs IA and navigation, compare and benchmarks pages),
  SEO/a11y/performance passes, /changelog with one page per release, llms.txt
  and raw-markdown alternates, and a reproducible competitor benchmark harness
  (`benchmarks/compare`, #719) feeding the site. (#687-#832)
- CI: VS Code extension publishes with Entra ID OIDC (#685, #686), website CI
  and Lighthouse budgets, weekly claims-drift check, Vercel preview opt-out
  with `[vercel skip]` (#821, #832), and internal review/plan files untracked
  (#822). Testcontainer startup in the schema loader tests is bounded by the
  test deadline, so a slow image pull skips instead of failing the package
  (#837).
- Docs: README rewrite with a compile-checked quickstart, refreshed pkg.go.dev
  docs for ParseTree (#713), all 30 lint rules documented (#785), the CHANGELOG
  1.0.0 upgrade guide and 1.9.1 entry (#824); `Server.Start`/`Server.Handler`
  document that they do not apply `RateLimitMiddleware`, and
  `docs/CHATGPT_APP.md` explains that ChatGPT users share OpenAI's per-IP limit
  (#841).
- CI: a Python Bindings workflow tests pygosqlx and the raw ctypes ABI on
  Linux and macOS with Python 3.10 and 3.13 (#847); `release.yml` pins the
  GoReleaser current and previous tags to the `v*` series so `pygosqlx-v*`
  tags cannot truncate the Go release changelog (#851), and the previous-tag
  lookup skips the floating Marketplace `v1` tag (#852); `vscode-publish.yml`
  stamps the tag version into the bundled binary and its smoke test fails if
  `--version` does not match, and the README quickstart job pins the latest
  tagged release explicitly (#846).
- Docs: new gosqlx.dev pages for Syntax Highlighting, the ChatGPT App,
  Upgrading GoSQLX (migration guide) and the `highlight` package API reference;
  `docs/api/lsp.md` documents semantic tokens and runtime dialect changes via
  `workspace/didChangeConfiguration`; `docs/api/linter.md` documents
  `Linter.SetDialect` and `gosqlx.LintWithDialect`; `MCP_GUIDE.md` states that
  `Server.Start`/`Server.Handler` apply no rate limiting unless wrapped in
  `NewRateLimitMiddleware` and that `lint_sql` runs only L001-L010; the
  migration guide and VS Code extension changelog gain their missing v1.15.0
  sections; `models.Location` documents byte columns and UTF-16 LSP
  conversion. (#848) The README describes `bigquery` and `redshift`
  accurately: generic keyword set plus some dialect-gated grammar. (#853)

## [1.15.0] - 2026-07-30 — Tree API, ClickHouse 100%, Oracle Gaps, Correctness Sweep

Covers everything merged between v1.14.0 and the October 2026 performance
audit: the high-level `Tree` API, ClickHouse at 83/83 of the QA corpus, Oracle
gaps, and two architect-review correctness sprints (#517, #518). Exported
signatures are unchanged apart from additions; read **Behavior changes**
before upgrading.

### Behavior changes
- **Linter rules inspect nested queries**: 14 built-in rules moved to `ast.Walk`
  and 6 more were reinforced, so violations inside subqueries and CTEs are now
  reported. Expect more findings on nested SQL. (#517)
- **Structured parser errors**: 37 `fmt.Errorf` sites in the parser now return
  structured `*errors.Error` values with position and code, and context
  cancellation returns `ctx.Err()` directly so `errors.Is(err,
  context.Canceled)` works. `*errors.Error.WithX` methods now copy instead of
  mutating the receiver. Legacy `Parse`-family functions wrap the
  `ErrSyntax`/`ErrTokenize`/`ErrTimeout`/`ErrUnsupportedDialect` sentinels.
  (#517, #518)
- **`parser.ValidateBytes("")` returns an error**, matching
  `gosqlx.Validate("")`. Snowflake stub statements (`USE`, `COPY INTO`, `PUT`,
  `GET`, `LIST`, `REMOVE`, `CREATE STAGE/STREAM/TASK/PIPE/...`) are now
  `*ast.UnsupportedStatement` instead of `*ast.DescribeStatement`. (#511)

### Added
- **High-level `Tree` API in `pkg/gosqlx`**: `ParseTree(ctx, sql, opts...)`
  returns an opaque `*Tree` with typed walkers (`WalkSelects`, `WalkInserts`,
  `WalkUpdates`, `WalkDeletes`, `WalkCreateTables`, `WalkJoins`, `WalkCTEs`,
  `WalkFunctionCalls`, `WalkIdentifiers`, `WalkBinaryExpressions`, generic
  `WalkBy[T]`), `Tree.Rewrite` and `Tree.Clone`. `FormatTree`/`FormatAST` format
  without re-parsing. Functional options `WithDialect`, `WithStrict`,
  `WithTimeout`, `WithRecovery` and `WithMaxBytes` replace the combinatorial
  `ParseWith*` helpers, which remain. `ParseReader`/`ParseReaderMultiple` read
  from an `io.Reader`, bounded by `WithMaxBytes`; `errors.Is(err,
  gosqlx.ErrTooLarge)` matches when the limit is exceeded. (#517, #518)
- **Dialect-aware `gosqlx.SplitStatements(sql, dialect)`**: splits a script on
  top-level `;`, honouring PostgreSQL dollar quoting and E-strings, nested block
  comments, MySQL backticks and SQL Server brackets. (#518)
- **One-call `gosqlx.Lint`, `gosqlx.Analyze` and error helpers**: `Lint(sql)`
  runs all 30 built-in rules, `Analyze(sql)` reports basic optimization hints and
  query complexity, and `ErrorCode`, `ErrorLocation` and `ErrorHint` unwrap
  structured error details through `fmt.Errorf` wrapping. (#512)
- **`pkg/sql/dialect`**: typed `Dialect` and a `Capabilities` struct with
  feature flags, exposed through `Parser.DialectTyped()`,
  `Parser.Capabilities()` and `Parser.Is<Dialect>()` helpers. (#517, #518)
- **`.gosqlx.yml` linter configuration (`pkg/linter/config`)**: YAML loader
  with rule enable/disable, severity overrides and ignore globs. (#517)
- **`keywords.Conflicts()`**: reports keyword registrations that collide across
  dialects; 11 silent conflicts were resolved. (#517)
- **`ast.UnsupportedStatement` and `AST.HasUnsupportedStatements()`**: parse-only
  Snowflake stubs are now their own node type, and the formatter emits
  `-- UNSUPPORTED: <raw SQL>` for them instead of corrupt SQL. (#511)
- **`EXTRACT(field FROM expr)`** parses. (#511)
- **ClickHouse at 83/83 of the QA corpus**: `ARRAY JOIN` / `LEFT ARRAY JOIN`
  (new `ArrayJoinClause`), scalar CTEs (`WITH <expr> AS <name>`),
  `CREATE MATERIALIZED VIEW` with `ENGINE`/`TO`, `CREATE TABLE ... AS <source>
  ENGINE = ...`, numeric `SAMPLE` arguments with `OFFSET`, and `LIMIT offset,
  count`. (#513)
- **Named `WINDOW` clause** (SQL:2003): `WINDOW w AS (PARTITION BY a ORDER BY
  b)`. (#513)
- **Oracle compatibility**: `ROWNUM`/`ROWID`/`LEVEL`/`SYSDATE` pseudo-columns
  with implicit aliases, `PIVOT`/`UNPIVOT` `IN` lists with `AS` aliases, and
  backslashes treated literally in string literals outside MySQL/PostgreSQL.
  (#513)
- **`SQL()` for `PragmaStatement`, `ShowStatement`, `DescribeStatement` and
  `ReplaceStatement`**. (#513)
- **`ast.PoolLeakCount()`**: counts work-queue entries dropped while releasing
  expressions. (#517)

### Changed
- **Deprecations**: `pkg/sql/monitor` is deprecated in favour of `pkg/metrics`.
  The legacy parser APIs `Parse([]token.Token)`,
  `ParseFromModelTokensWithPositions` and `ConversionResult.PositionMapping` are
  scheduled for removal in v2.0. (#511)
- **`pkg/sql/ast` source split**: `ast.go` and `pool.go` were split into
  statement, expression, clause and release files. No declarations changed.
  (#518)

### Fixed
- **Pool leaks**: `PutSelectStatement` released only some pooled fields, large
  `IN` lists overflowed the `PutExpression` work queue, and subqueries inside
  `IN`/`EXISTS`/`ANY`/`ALL`/array constructors were never released. (#517,
  #518)
- **`Children()` coverage**: 14 AST node types returned no children despite
  holding nodes, so `Walk`/`Inspect` skipped them. (#517)
- **LSP**: statement dispatch uses a type switch instead of `%T` string matching,
  and `documentSymbol` returns real ranges instead of line 0 to EOF. (#517)
- **Oracle and ClickHouse parsing**: `CONNECT BY` / `IS NULL` is no longer
  misread as a CTE, `SETTINGS` and numeric `SAMPLE` are no longer consumed as
  table aliases, and the SQL Server `OUTPUT` clause on INSERT parses in every
  dialect. (#513)
- **`gosqlx.ParseBytes`** passes bytes straight to the tokenizer, and seven
  previously skipped extraction cases (CASE, CAST, IN, BETWEEN, EXTRACT,
  recursive CTEs) are fixed. (#511)

### Security
- **Metrics error counters are bounded**: error statistics were keyed by
  `err.Error()`, an unbounded map that could exhaust memory. They are now
  counted per error code. (#517)
- **Trivy findings**: `golang.org/x/crypto` raised to v0.54.0 and
  `brace-expansion` pinned to `^5.0.8` in the VS Code extension. (#528)

### Internal
- CI: performance-regression and fuzz-regression jobs, `codecov.yml` thresholds,
  and the `bodyclose`/`noctx` linters (#512); a CI gate against new
  `p.dialect ==` comparisons (#518); race tests run through `task test:race`
  with a separate CGO `task test:cbinding` job (#513, #517).
- Website: site revamp, light-mode fixes and animations (#514, #515, #516).
- Docs: version and rule-count sweep (#510); integrations bumped to v1.14.0
  (#509).

## [1.14.0] - 2026-04-12 — Dialect-Aware Transforms, Snowflake 100%, Schema Introspection

Headline themes: dialect-aware transforms, Snowflake at 100% of the QA corpus, ClickHouse significantly expanded (83% of the QA corpus, up from 53%), live schema introspection, SQL transpilation, and first-class integration sub-modules (OpenTelemetry and GORM). Drop-in upgrade from v1.13.0 — no breaking changes.

### Added

#### Dialect-aware formatting (closes #479)
- **`transform.FormatSQLWithDialect(stmt, keywords.SQLDialect)`**: renders an AST using dialect-specific row-limiting syntax — `SELECT TOP n` for SQL Server, `FETCH FIRST n ROWS ONLY` for Oracle, `LIMIT n` for PostgreSQL/MySQL/SQLite/Snowflake/ClickHouse/MariaDB
- **`transform.ParseSQLWithDialect(sql, keywords.SQLDialect)`**: dialect-aware parsing convenience wrapper
- `FormatOptions.Dialect` field threads dialect through the formatter pipeline
- `normalizeSelectForDialect()` converts `Limit`/`Offset` into `TopClause` (SQL Server) or `FetchClause` (Oracle) on a shallow copy — original AST never mutated
- Parsed `TopClause` now renders (previously silently dropped — a long-standing bug)
- SQL Server pagination: `OFFSET m ROWS FETCH NEXT n ROWS ONLY` when both limit and offset are set
- PR #507

#### Snowflake dialect (100% QA corpus — 87/87 queries, epic #483)
- **`MATCH_RECOGNIZE`** clause (SQL:2016 R010): PARTITION BY, ORDER BY, MEASURES, ONE/ALL ROWS PER MATCH, AFTER MATCH SKIP, PATTERN, DEFINE (PR #506)
- **`@stage` references** in FROM clause with optional path and file format (PR #505)
- **`MINUS` as EXCEPT synonym** for Snowflake/Oracle (PR #494); fix for MINUS-as-alias edge case (PR #504)
- **`SAMPLE` / `TABLESAMPLE`** clause with BERNOULLI/ROW/SYSTEM/BLOCK methods (PR #501)
- **`QUALIFY`** clause for window-function filtering (Snowflake/BigQuery) (PR #490)
- **VARIANT colon-path expressions** (`expr:field.sub[0]`) (PR #496)
- **Time-travel** `AT`/`BEFORE`/`CHANGES` on table references (PR #495)
- **`LATERAL FLATTEN`** table function + named arguments (`name => expr`) (PR #492)
- **`TRY_CAST`** + `IGNORE NULLS` / `RESPECT NULLS` for window functions (PR #486)
- **`LIKE ANY`/`LIKE ALL`** and `ILIKE ANY`/`ILIKE ALL` quantifiers (PR #500)
- **`USE [WAREHOUSE|DATABASE|SCHEMA|ROLE]`** and `DESCRIBE` with object-kind prefixes (PR #491)
- **`COPY INTO`**, `PUT`, `GET`, `LIST`, `REMOVE` parse-only stubs (PR #499)
- **`CREATE STAGE`/`STREAM`/`TASK`/`PIPE`/`FILE FORMAT`/`WAREHOUSE`/`DATABASE`/`SCHEMA`/`ROLE`/`SEQUENCE`/`FUNCTION`/`PROCEDURE`** parse-only stubs (PR #498)
- **`CLUSTER BY`**, `COPY GRANTS`, and CTAS (`CREATE TABLE ... AS SELECT`) for CREATE TABLE (PR #504)
- **`ILIKE`** + PIVOT/UNPIVOT support for Snowflake dialect (PR #484)

#### ClickHouse dialect (69/83 QA corpus — 83%, up from 53% in v1.13.0, epic #482)
- Remaining ClickHouse QA gaps (tracked for v1.15): ARRAY JOIN / LEFT ARRAY JOIN, LIMIT n,m BY, named window definitions, scalar CTE subqueries, CREATE MATERIALIZED VIEW / DISTRIBUTED TABLE, SAMPLE with decimal and OFFSET, standalone SELECT ... SETTINGS without preceding FROM/WHERE
- **Reserved-word identifiers**: `table`, `partition`, `tables`, `databases` now valid as column/identifier names (closes #480, PR #481)
- **Nested column types**: `Nullable(T)`, `Array(T)`, `Map(K,V)`, `LowCardinality(T)` in CREATE TABLE (PR #488)
- **Engine clauses**: `MergeTree()`, `ORDER BY`, `PARTITION BY`, `PRIMARY KEY`, `SAMPLE BY`, `TTL`, `SETTINGS` (PR #488)
- **Parametric aggregates**: `quantile(0.95)(duration)` double-paren syntax (PR #487)
- **Bare-bracket array literals**: `[1, 2, 3]` without ARRAY keyword (PR #485)
- **`ORDER BY ... WITH FILL`** with FROM/TO/STEP (PR #493)
- **`CODEC(...)`** column compression option (PR #497)
- **`WITH TOTALS`** in GROUP BY, **`LIMIT ... BY`** clause, **ANY/ALL JOIN** strictness prefix, `DEFAULT` as identifier (PR #503)
- **`SETTINGS`** clause on SELECT and in CREATE TABLE, **`TTL`** column clause, **`INSERT ... FORMAT`** (JSONEachRow, CSV, Parquet, etc.) (PR #489)

#### MariaDB dialect
- New `DialectMariaDB` extending MySQL (`mariadb`) (PR #431)
- **SEQUENCE DDL**: `CREATE/DROP/ALTER SEQUENCE` with full option set (START WITH, INCREMENT BY, MINVALUE/MAXVALUE, CYCLE, CACHE, NOCACHE)
- **Temporal tables**: `FOR SYSTEM_TIME`, `WITH SYSTEM VERSIONING`, `PERIOD FOR`
- **Hierarchical queries**: `CONNECT BY` with `PRIOR`, `START WITH`, `NOCYCLE`
- Added to playground and WASM dialect map (PR #432)

#### SQL Server enhancements
- **PIVOT / UNPIVOT** clause parsing (T-SQL) (PR #477)

#### SQL Transpilation (`pkg/transpiler`)
- **`Transpile(sql, from, to keywords.SQLDialect)`**: composable rewrite-rule pipeline for cross-dialect conversion (PR #449)
  - MySQL → PostgreSQL: `AUTO_INCREMENT` → `SERIAL`/`BIGSERIAL`, `TINYINT(1)` → `BOOLEAN`
  - PostgreSQL → MySQL: `SERIAL` → `INT AUTO_INCREMENT`, `ILIKE` → `LOWER() LIKE LOWER()`
  - PostgreSQL → SQLite: `SERIAL`/`BIGSERIAL` → `INTEGER`, array types → `TEXT`
- **`gosqlx.Transpile()`** top-level convenience wrapper
- **`gosqlx transpile --from <dialect> --to <dialect>`** CLI subcommand

#### Live schema introspection (`pkg/schema/db`)
- **`Loader` interface** with `DatabaseSchema`/`Table`/`Column`/`Index`/`ForeignKey` types (PR #448)
- **PostgreSQL loader** (`pkg/schema/postgres`): introspects tables, columns (with primary/unique flags), indexes, and foreign keys via `information_schema` and `pg_catalog`
- **MySQL loader** (`pkg/schema/mysql`): introspects tables, columns, indexes, and foreign keys via `information_schema`
- **SQLite loader** (`pkg/schema/sqlite`): introspects via PRAGMA commands (pure Go, no cgo)
- **`gosqlx.LoadSchema()`** top-level dialect-agnostic convenience wrapper
- Integration tests using `testcontainers-go` v0.32.0 for PostgreSQL and MySQL loaders

#### DML Transform API (`pkg/transform`)
- `AddSetClause`, `SetClause`, `RemoveSetClause`, `ReplaceSetClause` for UPDATE statements (PR #446)
- `AddReturning`, `RemoveReturning` for INSERT/UPDATE/DELETE (PR #446)

#### Linter — expanded from 10 to 30 rules (PR #445)
- New rule categories: **safety**, **performance**, **naming** (alongside existing style and whitespace)
- Rules cover SQL injection patterns, missing WHERE clauses on UPDATE/DELETE, implicit type conversions, inconsistent identifier casing, table aliasing conventions, and more
- See `docs/LINTING_RULES.md` for full reference

#### Optimization Advisor (`pkg/advisor`)
- 12 new optimization rules: **OPT-009 through OPT-020** (PR #464)
- `gosqlx optimize` CLI subcommand runs the full advisor pipeline

#### Fingerprinting (`pkg/fingerprint`)
- **`Normalize(sql)`** canonicalizes literals (`WHERE id = 123` → `WHERE id = ?`) (PR #463)
- **`Fingerprint(sql)`** returns SHA-256 hash of normalized query for deduplication and query caches
- Integration with advisor and linter for aggregated findings

#### Integrations (sub-modules)
- **`integrations/opentelemetry/`**: `InstrumentedParse()` wraps `gosqlx.Parse()` with OpenTelemetry spans including `db.system`, `db.statement.type`, `db.sql.tables`, `db.sql.columns` attributes (PR #451)
- **`integrations/gorm/`**: GORM plugin that records executed query metadata (tables, columns, statement type) via GoSQLX parsing with GORM SQL normalization (backtick identifiers, `?` placeholders); exposes `Stats()` and `Reset()` APIs (PR #452)
- CI workflow for integration sub-modules (`.github/workflows/integrations.yml`)

#### Parser / AST additions
- **DDL formatter**, **`CONNECT BY`** hierarchical queries, **`SAMPLE`** clause (PR #472)
- **JSON function parsing** improvements (PR #460)
- **`gosqlx stats`** CLI subcommand exposes object pool utilization (PR #459)
- **`gosqlx watch`** CLI subcommand for continuous validation (PR #458)
- **`gosqlx action`** GitHub Actions integration with inline annotations (PR #443)

#### C binding
- Coverage hardened from **18% to 93%** via comprehensive test suite (PR #447)

#### Docs, website, and CI
- "Who's Using GoSQLX" section in README (PR #475)
- OpenSSF Scorecard security analysis workflow (PR #443)
- Sentry → GitHub Issues automation (PR #438)
- Website: mobile responsiveness improvements (PR #441), comprehensive a11y/UX audit (PR #440)
- MariaDB + Snowflake added to playground dialect dropdown (PR #432)

### Changed
- **OpenTelemetry SDK** bumped from v1.42.0 to v1.43.0 to address **CVE-2026-39883** (PR #502)
- Linter rule count exposed in glama.json, docs, and CLI help (10 → 30)
- Docs: SQL compatibility matrix updated to reflect Snowflake and ClickHouse 100% pass rate

### Fixed
- **SQL Server TOP rendering**: parsed `TopClause` values now correctly render in formatted output (PR #507). Round-trippers that parse `SELECT TOP 10 * FROM users` and format again will see `TOP 10` preserved — previously it was silently dropped.
- **Snowflake ILIKE + PIVOT/UNPIVOT** parse-time fix (PR #484)
- **MINUS consumed as select-list alias**: `SELECT 1 MINUS SELECT 2` now correctly treats MINUS as a set operator (PR #494)
- **ClickHouse production playground WASM 404**: committed `gosqlx.wasm` to git, removed auto-commit step blocked by branch protection (PRs #423, #424)
- **Playground React error #310**: `useState`/`useCallback` now above early returns (PR #429)
- Website: Vercel Analytics, Speed Insights, and CSP fixes (PR #433); Sentry hydration mismatch (PRs #434, #437, #439)
- CI: `testcontainers` skip on Windows; `.trivyignore` entries for unfixable transitive CVEs; graceful handling of `glama-sync` on non-GA runners

### Deprecated
Carried over from v1.13.0 (no new deprecations in v1.14.0):
- `parser.Parse([]token.Token)` — use `ParseFromModelTokens` instead
- `ParseFromModelTokensWithPositions` — consolidated into `ParseFromModelTokens`
- `ConversionResult.PositionMapping` — always nil, will be removed in v2

### Security
- **CVE-2026-39883** (HIGH, `go.opentelemetry.io/otel/sdk`): resolved by upgrading to v1.43.0 (PR #502)
- **`.trivyignore`** entries audited and documented — all remaining ignores are transitive test-only (Docker via testcontainers) or npm-only (website build-time dependencies, not shipped in Go binaries)

### Companion releases
- **VS Code extension**: bumped to **1.14.0** — tracks library version, no behavioral changes
- **MCP server**: bumped to **1.14.0** — glama.json updated with MariaDB and ClickHouse in dialect list
- **`pygosqlx` Python bindings**: bumped to **0.2.0** — Python bindings follow an independent semver track (alpha) since they have not yet received the same QA sweep as the core library

## [1.13.0] - 2026-03-20 — ClickHouse Dialect & LSP Semantic Tokens

### Added
- ClickHouse SQL dialect support (`DialectClickHouse = "clickhouse"`) with 30+ keywords
- `PrewhereClause` field on `SelectStatement` AST for ClickHouse PREWHERE optimization
- `Final` field on `TableReference` for ClickHouse MergeTree FINAL modifier
- PREWHERE clause parsing in ClickHouse dialect mode
- FINAL modifier parsing in ClickHouse dialect mode
- GLOBAL IN / GLOBAL NOT IN expression parsing (ClickHouse)
- ClickHouse data types: FixedString, LowCardinality, Nullable, DateTime64, IPv4, IPv6
- MergeTree engine family keywords (MERGETREE, REPLACINGMERGETREE, AGGREGATINGMERGETREE, etc.)
- LSP semantic token provider (`textDocument/semanticTokens/full`) with 6-type legend: keyword, identifier, number, string, operator, comment
- LSP diagnostic debouncing (300ms) — prevents excessive re-parsing on rapid typing
- LSP document cleanup on `textDocument/didClose`
- Glama MCP registry integration with stdio transport support
- Auto-trigger Glama build on GitHub release via CI (`glama-sync.yml`)
- Sentry error monitoring, tracing, and session replay on website

### Changed
- `ParseFromModelTokens` is now the canonical parse entry point (positions always populated)
- Docker base image Go 1.25 → 1.26 to match go.mod requirement
- Next.js 16.1.6 → 16.1.7 (CVE-2026-27979, CVE-2026-27980, CVE-2026-29057)
- Website rebuilt on Next.js 16 App Router with comprehensive a11y, SEO, and performance audit
- Lighthouse Desktop: 100 Performance / 100 Accessibility / 100 SEO (maintained)
- CI: Vercel deployment working-directory bug fixed (doubled path `website/website/`)

### Deprecated
- `parser.Parse([]token.Token)` — use `ParseFromModelTokens` instead
- `ParseFromModelTokensWithPositions` — consolidated into `ParseFromModelTokens`
- `ConversionResult.PositionMapping` — always nil, will be removed in v2

### Fixed
- Production playground WASM 404 (CI working-directory path doubling)
- WASM service worker cache versioning
- Broken `.md` relative links in docs → `/docs/` URL paths
- JSON-LD BreadcrumbList and Article markup on docs pages
- Horizontal overflow at 320–390px viewport
- Keyboard accessibility (tabIndex) on scrollable code blocks

## [1.12.1] - 2026-03-15 — Website Performance & Mobile Optimization

### Improved
- Lighthouse Desktop: 100 Performance, 100 Accessibility, 100 SEO
- Lighthouse Mobile: 94 Performance, 100 Accessibility, 100 SEO
- CLS reduced from 0.382 to 0 (removed stats animation, added image dimensions, font-size-adjust)
- FCP improved from 2.7s to 2.0s on mobile (self-hosted fonts via @fontsource)
- LCP improved from 3.0s to 2.4s on mobile
- Self-hosted fonts eliminate external Google Fonts request
- AnalyzeTab lazy-loaded via React.lazy() (328KB -> 3.4KB initial chunk)
- WebP logo (7KB vs 134KB PNG)
- Non-blocking font loading with preload/swap pattern

### Fixed
- 20 mobile responsiveness fixes (touch targets, overflow, responsive layout)
- Design consistency (unified cards, buttons, code blocks, padding across all pages)
- WCAG contrast (text-slate-500 -> text-slate-400 for readable text)
- Navbar backdrop-blur for visual separation from hero
- OFL-1.1 license added to CI allow-list for fontsource packages

### Changed
- README redesigned from 1,209 to 215 lines with visual feature grid
- Emdashes replaced with hyphens across 122 files

## [1.12.0] - 2026-03-15 — Custom Domain & Remote MCP Server

### Added
- Custom domain `gosqlx.dev` for the product website
- Custom domain `mcp.gosqlx.dev` for the remote MCP server
- Remote MCP server deployed on Render with smart 3-layer rate limiting
- Rate limiter: tiered IP limits, adaptive load scaling, tool-aware cost weighting
- Handler() and Cfg() methods on MCP Server for middleware composition
- Health endpoint at `/health` with version info
- Dockerfile for containerized MCP server deployment
- render.yaml blueprint for Render deployment
- GitHub Actions workflow for MCP server deployment

### Changed
- Website migrated from `ajitpratap0.github.io/GoSQLX/` to `gosqlx.dev`
- MCP server accessible at `mcp.gosqlx.dev` (previously local-only)
- All documentation URLs updated to use custom domains

### Fixed
- Website audit: 19 fixes across performance, security, accessibility, design, QA
- Lazy WASM loading on homepage (static preview, load on interaction)
- SEO: sitemap, robots.txt, structured data, Twitter cards, RSS feed

## [1.11.1] - 2026-03-15 — Website Polish & SEO

### Fixed
- WASM loading race condition and format parsing in playground
- CSP blocking Astro inline scripts (added unsafe-inline to script-src)
- Base path trailing slash for WASM asset loading
- 19 website audit fixes: broken doc links, mobile layout, accessibility, design tokens
- Hero playground output height and AnalyzeTab CSS conflict

### Improved
- Lazy WASM loading: homepage shows static preview, loads WASM only on user interaction
- Download progress bar for WASM in playground
- Typography: IBM Plex Mono headings, Instrument Sans body
- Hero section: gradient glow effects, gradient headline text
- Feature cards: SVG icons replacing emojis, hover glow effects
- Code examples: Go syntax highlighting with colored spans
- SEO: sitemap, robots.txt, JSON-LD structured data, Twitter cards, RSS feed
- Accessibility: ARIA tab roles, keyboard focus styles, semantic landmarks
- Design tokens: consistent color system replacing raw hex values

## [1.11.0] - 2026-03-14 — Product Website with WASM Playground

### Added
- Full product website built with Astro, React, and Tailwind CSS
- Interactive WASM-powered SQL playground with 4 tabs (AST, Format, Lint, Analyze)
- Documentation hub rendering 32+ existing markdown docs with sidebar navigation
- Blog/release notes auto-generated from CHANGELOG.md
- VS Code extension page with install instructions
- Benchmarks page with performance data
- GitHub Actions deployment to GitHub Pages
- gosqlxAnalyze WASM function for security + optimization analysis
- Dialect parameter support for all WASM functions

## [1.10.4] - 2026-03-14 — AST-based LSP Formatting

### Fixed
- LSP formatting now uses the full AST-based formatter instead of basic line indentation

## [1.10.3] - 2026-03-14 — LSP --stdio compatibility

### Fixed
- Accept --stdio flag in gosqlx lsp command (required by vscode-languageclient)
- Allow empty executablePath in config validation (uses bundled binary fallback)

## [1.10.2] - 2026-03-14 — VS Code Extension Fix

### Fixed
- Include node_modules in VSIX package (vscode-languageclient was missing)
- Add VS Code Marketplace badge and installation section to README

## [1.10.1] - 2026-03-13 — VS Code Marketplace Publishing

### ✨ New Features
- **VS Code Extension on Marketplace**: Extension now published with bundled platform-specific binaries
  - 5 platforms: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64
  - Smart binary resolution: bundled → user setting → PATH fallback
  - Automated CI publishing on every GoSQLX release tag

---

## [1.10.0] - 2026-03-13 — MCP Server

### ✨ New Features
- **MCP Server** (`pkg/mcp/`, `cmd/gosqlx-mcp/`): All GoSQLX SQL capabilities as Model Context Protocol tools over streamable HTTP
  - 7 tools: `validate_sql`, `format_sql`, `parse_sql`, `extract_metadata`, `security_scan`, `lint_sql`, `analyze_sql`
  - Optional bearer token auth via `GOSQLX_MCP_AUTH_TOKEN`
  - `analyze_sql` fans out all 6 tools concurrently via `sync.WaitGroup`
  - Multi-dialect validation: postgresql, mysql, sqlite, sqlserver, oracle, snowflake, generic

### 📝 Documentation
- `docs/MCP_GUIDE.md` — comprehensive MCP server guide
- `README.md` — MCP feature bullet, installation block, docs table entry
- `docs/ARCHITECTURE.md` — MCP in application layer diagram, new MCP Architecture section
- `docs/API_REFERENCE.md` — pkg/mcp package docs
- `docs/CONFIGURATION.md` — MCP env vars reference
- Go version references updated from 1.21+ to 1.23+ (required by mark3labs/mcp-go)

### 🔧 Build
- Go minimum bumped to 1.23.0 (required by `github.com/mark3labs/mcp-go v0.45.0`)
- Taskfile: `mcp`, `mcp:build`, `mcp:test`, `mcp:install` tasks added

---

## [1.9.3] - 2026-03-08 — License Detection Fix

### 🐛 Bug Fixes
- Replace LICENSE files with exact official Apache 2.0 text for pkg.go.dev detection (PR #356)
- Fix cobra command version string consistency (PR #354)
- Fix remaining 1.9.0 version references in doc comments (PR #355)

### 📝 Note
v1.9.2 was cached by the Go module proxy before the LICENSE fix landed,
so pkg.go.dev could not detect the license. This release ensures the
corrected LICENSE is served for `go get` users.

---

## [1.9.2] - 2026-03-08 — Documentation, Community Health & License Fixes

### 📚 Documentation (PR #351)
- Fix pkg.go.dev license detection (Apache-2.0 now properly detected)
- Comprehensive doc improvements across the project

### 🌍 Community (PR #350)
- Open-source health files (CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, etc.)
- LLM discovery metadata (llms.txt, llms-full.txt)
- SEO improvements for project discoverability

### 🐛 Bug Fixes (PR #352)
- Fix leading blank line in vscode-extension/LICENSE

---

## [1.9.1] - 2026-02-28 — Documentation & Community Health

Documentation and community-health release; no runtime behavior changes.
(These changes were also announced in the 1.9.2 notes.)

### 📚 Documentation (PR #351)
- Fix pkg.go.dev license detection and add comprehensive doc comments across
  `pkg/sql/ast`, `pkg/transform`, `pkg/sql/parser`, `pkg/errors`, `pkg/models`,
  `pkg/formatter`, `pkg/gosqlx` and the tokenizer packages

### 🌍 Community (PR #350)
- Open-source health files (issue and discussion templates, SUPPORT.md, etc.)
- LLM discovery metadata and SEO improvements for project discoverability

---

## [1.9.0] - 2026-02-28 - SQLite PRAGMA, Tautology Detection & 19 Post-UAT Fixes

19 actionable bugs fixed (PR #348) — 3 new capabilities, 8 parser fixes,
5 CLI output bugs, 3 CLI UX improvements, 2 security scanner improvements.

### Highlights
- SQLite PRAGMA statement fully implemented (bare, arg, and assignment forms)
- WITHOUT ROWID support in CREATE TABLE
- Tautology injection detection (1=1, 'a'='a', OR TRUE) → CRITICAL
- UNION false-positive eliminated: generic UNION is now HIGH, not CRITICAL
- lint command usable as CI gate (exits 1 on any violation)
- token_count, Query Size, CTE output, and SELECT indentation all fixed

### ✨ Features
[DIALECT-3] SQLite PRAGMA parsing — PragmaStatement AST node + pragma.go parser
[DIALECT-4] SQLite WITHOUT ROWID on CREATE TABLE; reserved keywords as DDL column names
[SEC-1]     Tautology detection in ScanSQL(): numeric/string/identifier/OR TRUE patterns

### 🐛 Bug Fixes
[ERR-1]     E1009 ErrCodeUnterminatedBlockComment replaces generic E1002 for /* ... */
[DIALECT-1] MySQL backtick-quoted reserved words now parsed as identifiers
[DIALECT-2] SQL Server bracket-quoted reserved words now parsed as identifiers
[CORE-1]    KEY/INDEX/VIEW reserved keywords now valid in qualified identifiers (a.key)
[CORE-2]    NATURAL JOIN stores type "NATURAL" not "NATURAL INNER"
[CORE-3]    OVER <window_name> (bare name, no parens) now supported per SQL:2003 §7.11
[CLI-1/2]   token_count uses actual tokenizer output count
[CLI-3]     analyze Query Size shows real character and line counts
[CLI-4]     format first SELECT column is now correctly indented
[CLI-5]     parse output includes has_with/cte_count for CTE queries
[CLI-6]     validate no longer prints usage block on domain errors
[CLI-7]     lint exits 1 when any violation found (usable as CI gate)
[CLI-8]     validate output standardized to ✅/❌

### 🔒 Security
[SEC-2]     UNION detection split: PatternUnionInjection (CRITICAL, system tables +
            NULL padding) and PatternUnionGeneric (HIGH, generic UNION SELECT)
            — eliminates false-positive CRITICAL on legitimate application queries

---

## [1.8.0] - 2026-02-24 - Multi-Dialect Engine, Query Transform API, WASM Playground & Token Type Overhaul

This release represents the largest update since v1.0.0 with **74 commits** across 30+ PRs. It introduces a dialect-aware parsing engine with full MySQL syntax support, a programmatic Query Transform API, WebAssembly browser playground, comment-preserving formatter, AST-to-SQL serialization, and completes a multi-phase token type refactor that delivers ~50% faster parsing.

### Highlights
- **Dialect Mode Engine**: Thread SQL dialect through tokenizer and parser with `ParseWithDialect()` / `--dialect` CLI flag
- **MySQL Syntax Support**: SHOW, DESCRIBE, REPLACE INTO, ON DUPLICATE KEY UPDATE, LIMIT offset/count, GROUP_CONCAT with SEPARATOR, MATCH AGAINST, REGEXP/RLIKE
- **Query Transform API**: Programmatic SQL rewriting — add WHERE clauses, columns, JOINs, pagination, rename tables via composable rules
- **WASM Playground**: Browser-based SQL parsing, formatting, linting, and validation via WebAssembly
- **Comment Preservation**: SQL comments survive parse-format round-trips
- **AST-to-SQL Serialization**: `SQL()` methods on all AST nodes enable full roundtrip support
- **Token Type Overhaul (BREAKING)**: Legacy string-based `token.Type` removed; all token comparisons now use O(1) integer operations (~50% faster parsing)
- **AST-based Formatter**: Configurable SQL formatter with CompactStyle/ReadableStyle presets and keyword casing options
- **DDL Formatters**: Format() methods for ALTER TABLE, CREATE INDEX/VIEW, DROP, TRUNCATE and more
- **Error Recovery**: Multi-error parsing with `ParseWithRecovery()` for IDE-quality diagnostics
- **Dollar-Quoted Strings**: PostgreSQL `$$body$$` and `$tag$body$tag$` tokenizer support
- **~50% Faster Parsing**: Token type unification eliminates string comparisons on all hot paths

---

### ✨ Features

#### Dialect Mode Engine (PR #315, closes #249 Phase 1)
- `tokenizer.NewWithDialect(dialect)` constructor for dialect-aware keyword recognition
- `tokenizer.SetDialect(dialect)` to reconfigure pooled tokenizers
- `parser.WithDialect(dialect)` parser option
- `parser.ParseWithDialect(sql, dialect)` / `ValidateWithDialect(sql, dialect)` convenience functions
- `ParseBytesWithDialect` / `ValidateBytesWithDialect` byte-slice variants
- CLI `--dialect` flag for `validate` and other commands
- Defaults to PostgreSQL for backward compatibility

#### MySQL Syntax Support (PR #316, closes #249 Phase 2)
- **LIMIT offset, count**: MySQL-style `LIMIT 10, 20` (offset first, then count)
- **ON DUPLICATE KEY UPDATE**: MySQL upsert syntax for INSERT statements
- **SHOW statements**: `SHOW TABLES`, `SHOW DATABASES`, `SHOW CREATE TABLE x`
- **DESCRIBE/EXPLAIN**: Table description commands
- **REPLACE INTO**: MySQL-specific insert-or-replace statement
- **UPDATE/DELETE with LIMIT**: MySQL extension for limiting affected rows
- **INTERVAL number unit**: MySQL-style `INTERVAL 30 DAY` (in addition to PostgreSQL's `INTERVAL '30 days'`)
- **IF()/REPLACE() functions**: Keywords usable as function names in MySQL mode
- **GROUP_CONCAT**: With ORDER BY and SEPARATOR clause support
- **MATCH AGAINST**: Full-text search expressions
- **REGEXP/RLIKE**: Regular expression operators
- New AST nodes: `ShowStatement`, `DescribeStatement`, `ReplaceStatement`
- New token types: `TokenTypeShow`, `TokenTypeDescribe`, `TokenTypeExplain`
- 30 MySQL test data files, 15+ unit tests

#### Query Rewriting/Transform API (PR #285, closes #247)
- New `pkg/transform/` package for programmatic SQL modification via AST manipulation
- **WHERE**: `AddWhere`, `RemoveWhere`, `ReplaceWhere`, `AddWhereFromSQL`
- **Columns**: `AddColumn`, `RemoveColumn`, `ReplaceColumn`, `AddSelectStar`
- **JOINs**: `AddJoin`, `RemoveJoin`, `AddJoinFromSQL`
- **Tables**: `ReplaceTable`, `AddTableAlias`, `QualifyColumns`
- **LIMIT/OFFSET**: `SetLimit`, `SetOffset`, `RemoveLimit`, `RemoveOffset`
- **ORDER BY**: `AddOrderBy`, `RemoveOrderBy`
- `Rule` interface with `Apply(stmt)` and `RuleFunc` adapter for composable rule chaining
- 5 documented examples: multi-tenant filtering, column projection, JOIN injection, pagination, table migration
- 28 tests across 6 test files

#### Comment Preservation in AST and Formatter (PR #311, closes #275)
- `models.Comment` type for representing SQL comments with position information
- Tokenizer captures line (`--`) and block (`/* */`) comments during tokenization
- AST stores captured comments and emits them during formatting
- Formatter preserves comments through parse-format round-trips
- AST pool properly resets comments on release

#### WASM Build + Web Playground (PR #309, closes #226)
- WebAssembly build target for browser-based SQL parsing
- WASM bindings for parse, format, lint, and validate operations
- Single-page playground with split-pane UI
- Ready for GitHub Pages deployment

#### AST-to-SQL Serialization with Roundtrip Support (PR #234, closes #221)
- `SQL()` methods on all AST node types: SELECT, INSERT, UPDATE, DELETE, CREATE TABLE/INDEX/VIEW, ALTER TABLE, DROP, TRUNCATE, MERGE, CTEs, set operations
- Expression serialization: Binary, Unary, CASE, CAST, BETWEEN, IN, EXISTS, IS NULL, LIKE, subqueries, function calls, EXTRACT, POSITION, SUBSTRING, INTERVAL
- Clause serialization: WHERE, JOIN, ORDER BY, GROUP BY, HAVING, LIMIT, OFFSET, FETCH, FOR UPDATE, window functions, DISTINCT ON, LATERAL, RETURNING, ON CONFLICT
- 29 roundtrip tests verifying `parse(sql).SQL()` → parse again → idempotent

#### AST-based SQL Formatter with Style Presets (PR #265, closes #244)
- `FormatOptions` struct with configurable indent style (spaces/tabs), indent width, keyword case (upper/lower/preserve), line width
- **CompactStyle**: Minimal whitespace, single-line output, preserved keyword case
- **ReadableStyle**: Indented, keywords uppercase, one clause per line, semicolons
- `gosqlx.Format()` updated to use AST-based formatting
- 12 tests covering both styles, keyword casing, roundtrip verification, all major statement types

#### DDL Statement Formatters (PR #284, closes #271)
- `Format()` methods for: AlterTableStatement (ADD/DROP COLUMN, constraints, multi-action), CreateIndexStatement (UNIQUE, IF NOT EXISTS, USING, WHERE), CreateViewStatement (OR REPLACE, TEMPORARY), CreateMaterializedViewStatement (TABLESPACE, WITH DATA), RefreshMaterializedViewStatement (CONCURRENTLY), DropStatement (IF EXISTS, CASCADE/RESTRICT), TruncateStatement (RESTART/CONTINUE IDENTITY)
- 23 new tests covering compact and readable styles

#### Error Recovery for Multi-Error Parsing (PR #236, closes #218)
- Parser error recovery: synchronizes to next statement on error and continues parsing
- Returns partial AST with all collected errors for IDE-quality diagnostics

#### ParseWithRecovery API + LSP Integration (PR #264, closes #245)
- `gosqlx.ParseWithRecovery()` high-level API returning partial AST and all errors
- LSP `validateDocument` upgraded to use `ParseWithRecovery` for multi-error diagnostics
- 8 new LSP functional tests covering diagnostics, completion, and hover

#### Dollar-Quoted String Support (PR #233, closes #217)
- PostgreSQL `$$body$$` and `$tag$body$tag$` syntax in tokenizer
- Handles empty tags, named tags, nesting, multiline, unterminated errors
- Security scanner strips dollar-quoted content to prevent bypass and false positives
- 13 tokenizer + 5 security tests

#### Schema-Aware Validation Package (PR #209, closes #82)
- `pkg/schema/` with constraint validation: NOT NULL checking for INSERT/UPDATE
- Type compatibility checking for INSERT values vs column types
- Foreign key integrity validation
- Object pooling for validation maps; case-insensitive table/column lookups

#### Query Optimization Engine (PR #210, closes #81)
- `pkg/advisor/` (renamed from `pkg/optimizer/` in PR #261) with 12 optimization rules
- Rules OPT-001 through OPT-012: SELECT * detection, missing WHERE, Cartesian products, DISTINCT overuse, subquery in WHERE, OR in WHERE, leading wildcard LIKE, function on indexed column, N+1 query detection, index recommendations, join order optimization, query cost estimation
- CLI command `gosqlx optimize` with text/JSON output
- Complexity scoring and query classification

#### Snowflake Dialect Support (PR #211)
- Snowflake dialect keyword detection and support
- Multi-dialect detection engine with weighted scoring
- Dialect-specific keyword sets for Snowflake, PostgreSQL, MySQL, SQL Server, Oracle, SQLite

#### Python Bindings Foundation (PR #208, closes #75)
- CGo shared library (`pkg/cbinding/`) for FFI integration
- Python package `pygosqlx` with parse, validate, format, extract_tables APIs
- Thread-safe and memory-safe via ctypes FFI

#### GitHub Action for SQL Lint + Validation (PRs #237, #259, closes #223, #242)
- GitHub Action published to marketplace as **GoSQLX Lint Action**
- Inputs: `sql-files`, `rules`, `severity`, `config`, `timeout`
- PR annotations (`::error`, `::warning`), SARIF output support
- Rewritten in Go as `gosqlx action` subcommand (PR #310, closes #251) for better error handling

#### Public Formatter Package (PR #307)
- `pkg/formatter/` with clean public API: `formatter.New(opts).Format(sql)` and `formatter.FormatString(sql)`

#### VSCode Extension + Editor LSP Docs (PR #263, closes #246)
- Updated VSCode extension for marketplace publishing
- Added Neovim and JetBrains LSP configuration documentation

#### Replace DebugLogger with slog (PR #262, closes #224)
- Custom `DebugLogger` interface replaced with Go standard `log/slog` (Go 1.21+)
- `SetLogger(*slog.Logger)` method replaces `SetDebugLogger`
- Structured debug logging guarded by level checks (zero cost when disabled)

---

### 🐛 Bug Fixes

#### Batch 1 — Critical Bug Fixes (PR #304, closes #288, #289, #291)
- **INSERT ... SELECT**: Parser now accepts `INSERT INTO ... SELECT` in addition to `INSERT INTO ... VALUES` with UNION support
- **Non-zero exit codes**: `format` and `lint` CLI commands now return non-zero exit codes on failure
- **SetLimit validation**: Added test coverage for negative values and zero

#### Batch 2 — UX/Consistency Fixes (PR #305, closes #290, #292, #294, #295)
- **Consistent inline SQL handling** for format/validate/lint commands
- **RemoveColumn** now returns error for missing columns instead of silent no-op
- **TTY detection**: CLI shows help instead of hanging when no input is piped
- **Trailing newline** added to format output
- Narrowed `InsertStatement.Query` to `QueryExpression` interface
- Named `Formatter` interface replaces ad-hoc type assertions

#### Batch 3 — Parser Strictness (PR #306, closes #296, #300)
- `SELECT FROM users` (missing column list) now returns error
- `SELECT * FROM users WHERE` (incomplete WHERE) now returns error
- `SELECT * FROM` (missing table name) now returns error
- `SELECT * FROM t1, t2` comma-separated tables now parse correctly
- `WithStrictMode()` parser option that rejects empty statements between semicolons

#### Batch 4 — Enhancements (PR #307, closes #273, #293, #297, #298, #299)
- **validate --check** quiet mode: `--check` alias for `--quiet`, only exit code produced
- **Wide SELECT proven O(n)**: Benchmark confirmed linear scaling (100→5000 columns)
- Pre-allocated columns/groupBy slices to reduce allocations
- Benchmark CI job fix: added `-run=^$` to skip regular tests, `-timeout=5m` safety net
- Additional UPSERT edge case test coverage

#### Architect Review Quick Wins (PR #312)
- Fixed `lintFile` ignoring `--rules` flag (functional bug)
- Added WASM build verification to CI
- Expanded golangci-lint config with misspell, gocritic checks

#### Other Fixes
- Fixed flaky `TestParseContext_Timeout` on Windows (PR #266)
- Consolidated `UpdateStatement` dual fields (PR #229, closes #216)
- Updated schema package to use `Assignments` instead of removed `Updates` field (PR #240)
- Removed legacy build tags for govet CI fix (PR #239)

---

### ⚡ Performance

#### ~50% Faster Parsing via Token Type Unification (PRs #252, #254, #255, #257, #258, #281, #267, #282, #283)
- All token type checks now use O(1) integer comparison instead of string comparison
- `matchToken()` migrated to O(1) `matchType()` across all 59 call sites
- Benchmark results on Apple M4:
  - SimpleSelect 10 cols: 1542 → 783 ns/op (**49% faster**)
  - SimpleSelect 100 cols: 9736 → 4843 ns/op (**50% faster**)
  - SimpleSelect 1000 cols: 83612 → 39487 ns/op (**53% faster**)
  - SingleJoin: 1425 → 621 ns/op (**56% faster**)
  - SimpleWhere: 736 → 373 ns/op (**49% faster**)

#### Validate() Fast Path (PR #308, closes #274)
- Skip full AST construction for validation-only calls

#### ParseBytes Zero-Copy (PR #308, closes #277)
- Avoid `string([]byte)` allocation in `ParseBytes`

#### Pool TokenConverter (PR #278, closes #269)
- Eliminate per-call map allocation via sync.Pool

#### Reduced Parser Test Runtime (PR #287, closes #273)
- Faster test suite execution

#### Full Pipeline Benchmark (PR #231, closes #222)
- `BenchmarkFullPipeline` covering tokenize→convert→parse for 10 query types
- `BenchmarkParseError` benchmarking error handling paths

---

### 🔧 Refactoring

#### Token Type Unification — Complete (#215, PRs #252, #254, #255, #257, #258, #281, #267, #282, #283)
- **Phase 1** (PR #252): `TokenType.String()` switch-based implementation, `ParseFromModelTokens()` entry point
- **Phase 2A** (PR #254): Core parser token infrastructure migration
- **Phase 2B** (PR #255): Remaining parser files migration
- **Phase 2C** (PR #257): Test files migration to `models.TokenType`
- **Phase 3A** (PR #258): `matchToken()` and remaining string Type usage migrated
- **Phase 3B** (PRs #281, #267): `ConvertTokensForParser` eliminated, `token_converter.go` deleted (~1,100 net lines removed)
- **Phase 4A** (PR #282): `matchToken()` to O(1) int comparison (~50% faster)
- **Phase 4B** (PR #283): **BREAKING** — Legacy `token.Type` string system removed, `ModelType` renamed to `Type`, net -1,680 lines

#### Split cmd/ Package into Sub-Packages (PR #314)
- Extracted `cmd/gosqlx/internal/lspcmd/`, `actioncmd/`, `optimizecmd/`, `cmdutil/`
- Each sub-package exports `NewCmd()` returning `*cobra.Command`
- Pure structural refactor, no behavior changes

#### Rename pkg/optimizer → pkg/advisor (PR #261, closes #243)
- Better reflects static analysis nature (pattern-matching rules, not query optimization)

#### Replace DebugLogger with slog (PR #262, closes #224)
- Replaces custom interface with Go standard `log/slog`

#### Resolve Remaining TODOs (PR #260, closes #248)
- Cleaned up tracked TODO items across the codebase

---

### 🔒 Security

#### Enhanced Security Scanner (PR #308, closes #276)
- LIKE injection detection patterns
- Blind injection detection (time-based, boolean-based)
- Enhanced tautology detection
- Rule registry architecture for extensible pattern matching
- Dollar-quoted string stripping prevents bypass and false positives (PR #233)

---

### 📦 CI/CD

- Consolidated CI workflows and updated action versions (PR #286)
- Re-enabled errcheck, govet, staticcheck linters (PR #235, closes #219)
- Lowered Go version requirement to 1.21+ (PR #228, closes #213)
- Added dedicated `-race` test CI job (PR #313)
- Added WASM build verification to CI (PR #312)
- Expanded golangci-lint config with misspell, gocritic (PR #312)
- GitHub Action rewritten in Go for reliability (PR #310, closes #251)

---

### 📚 Documentation

- Fixed README accuracy issues and updated for v1.7.0 (PR #207)
- Added VSCode extension and editor LSP setup documentation (PR #263)
- 5 documented transform API examples in `examples/transform/`
- Added `ACTION_README.md` for GitHub Action usage

---

### ⚠️ Breaking Changes

#### Token Type System Overhaul (PR #283, closes #215)

The legacy string-based `token.Type` system has been removed entirely. This is a breaking change for code that directly references the old string-based token types.

```go
// Before (v1.7.0 — string-based):
tok := token.Token{Type: token.SELECT, ModelType: models.TokenTypeSelect, Literal: "SELECT"}
if tok.Type == token.SELECT { ... }

// After (v1.8.0 — int-based):
tok := token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"}
if tok.Type == models.TokenTypeSelect { ... }
```

**What changed:**
- Removed `type Type string` from `pkg/sql/token`
- Removed `Type` (string) field from `token.Token` struct
- Renamed `ModelType` field to `Type` in `token.Token` (now `models.TokenType` int)
- Removed all string-based token constants (`token.SELECT`, `token.FROM`, etc.)
- Removed `stringTypeToModelType` bridge map and `normalizeTokens()`

**Who is affected:** Only users who directly access `token.Token` fields or use string-based token constants from `pkg/sql/token`. Users of the high-level `gosqlx.Parse()` / `gosqlx.Validate()` API are **not affected**.

See [Migration Guide](https://github.com/ajitpratap0/GoSQLX/blob/main/docs/MIGRATION.md) for detailed migration instructions.

---

### 🧪 Testing

- Fuzz testing for parser, security scanner, and formatter (PR #279, closes #270)
- AST and models test coverage boost (PR #280, closes #268)
- Negative parser test suite with pool contamination tests (PR #232, closes #220)
- Real-world SQL test corpus: TPC-H, TPC-DS, ORM patterns (PR #238, closes #225)
- Parser fuzz tests (PR #230, closes #214)
- Parser coverage improved from 79.8% to 84.7% (PR #206)
- gosqlx package coverage improved from 71.6% to 84.0% (PR #313)
- Added comprehensive MySQL test suite with 30 test data files (PR #316)

---

### 🔄 License

- Relicensed from AGPL to **Apache License 2.0** (PR #227, closes #212)

---

## [1.7.0] - 2026-02-12 - Parser Enhancements: Schema-Qualified Names, Array/Regex Operators & SQL Standards

This release delivers 9 commits with major parser enhancements across 4 feature batches, 2 critical bug fixes, and comprehensive test improvements. Schema-qualified table names (`schema.table`) now work across all statement types, and the parser gains support for ARRAY constructors, regex operators, INTERVAL expressions, FETCH/FOR UPDATE, multi-row INSERT, PostgreSQL UPSERT, type casting, and positional parameters.

### Highlights
- **Schema-Qualified Names**: `schema.table` and `db.schema.table` support in SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, TRUNCATE, JOIN (Fixes #202)
- **Double-Quoted Identifiers**: ANSI SQL quoted identifiers in all DML/DDL statements (#200, #201)
- **Parser Batches 5-8**: ARRAY constructors, WITHIN GROUP, JSONB operators, INTERVAL, FETCH, FOR UPDATE, multi-row INSERT, UPSERT, type casting (`::` operator), positional parameters (`$1`), array subscript/slice, regex operators, BETWEEN tests
- **Test Coverage**: 30+ new test cases for schema qualification, tuple IN expressions, quoted identifiers

---

### Added - Parser Enhancements Batch 5 (PR #187)

#### ARRAY Constructor Syntax (#182)
- `ARRAY[1, 2, 3]` constructor expression parsing
- Nested arrays: `ARRAY[ARRAY[1,2], ARRAY[3,4]]`
- Empty arrays: `ARRAY[]`

#### WITHIN GROUP Ordered-Set Aggregates (#183)
- `PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary)` syntax
- Supports PERCENTILE_DISC, MODE, and other ordered-set aggregates
- Added `WithinGroup` field to `FunctionCall` AST

#### JSONB Operators Enhancement
- Concatenation operator: `||` for JSONB
- Delete operators: `-` (key delete), `#-` (path delete)
- All 10 JSON/JSONB operators fully supported

---

### Added - Parser Enhancements Batch 6 (PR #196)

#### PostgreSQL UPSERT / ON CONFLICT (#193)
- `INSERT ... ON CONFLICT (columns) DO NOTHING` syntax
- `INSERT ... ON CONFLICT (columns) DO UPDATE SET ...` syntax
- `ON CONFLICT ON CONSTRAINT constraint_name` variant
- Added `OnConflict` AST node with target columns, constraint, and update actions

#### PostgreSQL Type Casting (#188)
- `expr::type` operator syntax (e.g., `'123'::INTEGER`, `column::TEXT`)
- Chained casts: `value::TEXT::VARCHAR(50)`
- Parameterized types: `name::VARCHAR(100)`
- Array types: `tags::TEXT[]`
- All standard data types supported

#### Positional Parameters (#195)
- `$1`, `$2`, `$N` parameter placeholders
- Works in all expression contexts (WHERE, SELECT, VALUES, etc.)

---

### Added - Parser Enhancements Batch 7 (PR #197)

#### INTERVAL Expressions
- `INTERVAL '1 year'`, `INTERVAL '30 days'` syntax
- Time intervals: `INTERVAL '2 hours 30 minutes'`
- Added `IntervalExpression` AST node

#### FETCH FIRST/NEXT Enhancements
- Extended FETCH clause with additional syntax variants
- Better SQL-99 compliance for OFFSET-FETCH patterns

#### FOR UPDATE / FOR SHARE (SQL:2003)
- `SELECT ... FOR UPDATE` row-level locking
- `SELECT ... FOR SHARE` shared locking
- `FOR UPDATE OF table_name` targeted locking
- `FOR UPDATE NOWAIT` / `FOR UPDATE SKIP LOCKED`
- Added `ForClause` AST node

#### Multi-row INSERT (#179)
- `INSERT INTO t VALUES (1, 'a'), (2, 'b'), (3, 'c')` syntax
- Updated `InsertStatement.Values` to `[][]Expression` for multi-row support

---

### Added - Parser Enhancements Batch 8 (PR #198)

#### Array Subscript and Slice (#180, #190)
- `array[1]` subscript access
- `array[1:3]` slice syntax
- Chained access: `matrix[1][2]`
- Added `ArraySubscriptExpression` AST node

#### Regex Operators (#191)
- `~` case-sensitive match
- `~*` case-insensitive match
- `!~` case-sensitive not match
- `!~*` case-insensitive not match

#### BETWEEN Expression Tests
- Comprehensive test suite for BETWEEN with complex expression bounds

---

### Fixed

#### Schema-Qualified Table Names (#202, PR #204)
- `SELECT * FROM schema.table_name` now parses correctly (was: E2002 error)
- Added `parseQualifiedName()` helper supporting up to 3-part names (`db.schema.table`)
- Applied to: SELECT FROM, JOIN, INSERT INTO, UPDATE, DELETE FROM, CREATE TABLE/VIEW/INDEX, DROP, TRUNCATE, REFRESH MATERIALIZED VIEW
- Removed "Schema-Qualified Table Names" from known parser limitations
- Enabled `TestExtractTablesQualified_WithSchema` with 6 test cases
- 24 new parser tests in `schema_qualified_test.go`

#### Double-Quoted Identifiers in DML/DDL (#200, PR #201)
- `isIdentifier()` now used instead of `isType(TokenTypeIdentifier)` across all parsers
- Fixed in: INSERT, UPDATE, DELETE, MERGE, CREATE, DROP, TRUNCATE, REFRESH, CTE, constraints
- 527 lines of new tests in `double_quoted_identifier_test.go`

---

### Improved

#### Documentation (PRs #185, #186)
- Comprehensive godoc documentation update across all packages
- Updated docs to reflect v1.6.0 features as available

#### Test Coverage
- Tuple expressions in IN clause: comprehensive tests (PR #199)
- Safe type assertions pattern applied across test files
- Performance regression test baselines updated for CI variability

---

### Known Issues (Resolved from v1.6.0)

The following issues from v1.6.0 Known Issues have been resolved:
- ~~**#179**: Multi-row INSERT VALUES syntax~~ → Fixed in PR #197
- ~~**#180**: BETWEEN with complex expression bounds~~ → Fixed in PR #198
- ~~**#181**: Tuple expressions in IN clause~~ → Tests added in PR #199
- ~~**#182**: PostgreSQL ARRAY constructor syntax~~ → Fixed in PR #187
- ~~**#183**: WITHIN GROUP ordered set aggregates~~ → Fixed in PR #187

### Remaining Known Issues
- **#178**: PostgreSQL JSONB existence operators (?, ?|, ?&) in parser (partial - tokenizer supports them)
- Oracle PL/SQL `CREATE OR REPLACE FUNCTION` not supported (part of #202 report)

## [1.6.0] - 2025-12-09 - Major Feature Release: PostgreSQL Extensions, LSP Server & Developer Tools

This release represents a major milestone with 20+ PRs merged, adding comprehensive PostgreSQL support, a full Language Server Protocol implementation, VSCode extension, and significant performance optimizations.

### Highlights
- **PostgreSQL Extensions**: LATERAL JOIN, JSON/JSONB operators, DISTINCT ON, FILTER clause, aggregate ORDER BY
- **Language Server Protocol**: Full LSP server for IDE integration with real-time diagnostics
- **VSCode Extension**: Official extension with syntax highlighting, formatting, and autocomplete
- **Performance**: 14x faster token type checking, 575x faster keyword suggestions with caching
- **Developer Experience**: go-task build system, 10 linter rules, structured error codes

---

### Added - PostgreSQL Features (PRs #173-#177)

#### LATERAL JOIN Support (#173)
- Added `Lateral bool` field to `TableReference` AST node
- Parser recognizes LATERAL in FROM and JOIN clauses
- Supports: `LEFT JOIN LATERAL`, `INNER JOIN LATERAL`, `CROSS JOIN LATERAL`
- CLI formatter properly outputs LATERAL keyword

#### ORDER BY inside Aggregates (#174)
- Added `OrderBy []OrderByExpression` field to `FunctionCall` AST
- Supports: STRING_AGG, ARRAY_AGG, JSON_AGG, JSONB_AGG, XMLAGG, GROUP_CONCAT
- Full modifier support: ASC/DESC, NULLS FIRST/LAST
- Works with window functions and complex expressions

#### JSON/JSONB Operators (#175)
- Arrow operators: `->`, `->>` (field access)
- Path operators: `#>`, `#>>` (path access)
- Containment: `@>`, `<@` (contains/contained by)
- Existence: `?`, `?|`, `?&` (key existence checks)
- Delete: `#-` (delete at path)
- Proper operator precedence in expression parsing
- Supports chained operators: `data -> 'a' -> 'b' ->> 'c'`

#### PostgreSQL DISTINCT ON (#171, PR #176)
- `SELECT DISTINCT ON (column1, column2) ...` syntax
- Multi-column expression support
- 8 comprehensive test cases

#### FILTER Clause (SQL:2003 T612, PR #176)
- `COUNT(*) FILTER (WHERE condition)` syntax
- Works with all aggregate functions
- 13 test cases covering edge cases

#### RETURNING Clause (#159, PR #164)
- PostgreSQL-style RETURNING for INSERT, UPDATE, DELETE
- Supports: column names, `*`, qualified names, expressions
- Added `TokenTypeReturning` (379) for RETURNING keyword

---

### Added - Language Server Protocol (PRs #128-#129)

#### LSP Server Implementation (CLI-009)
- JSON-RPC 2.0 protocol handler over stdio
- `textDocument/didOpen`, `textDocument/didChange`, `textDocument/didClose` - Document sync
- `textDocument/publishDiagnostics` - Real-time SQL syntax error reporting
- `textDocument/hover` - Keyword/function documentation (60+ keywords)
- `textDocument/completion` - SQL autocomplete (100+ keywords, 22 snippets)
- `textDocument/formatting` - SQL code formatting
- `textDocument/documentSymbol` - SQL statement outline navigation
- `textDocument/signatureHelp` - Function signatures (20+ SQL functions)
- `textDocument/codeAction` - Quick fixes (add semicolon, uppercase keywords)
- Rate limiting (100 req/sec), content size limits (10MB), document limits (5MB)
- Incremental document sync for better performance with large files
- Error position extraction from parser messages

#### Usage
```bash
gosqlx lsp              # Start LSP server on stdio
gosqlx lsp --log /tmp/lsp.log  # With debug logging
```

---

### Added - VSCode Extension (PRs #132, #135)

#### Official GoSQLX Extension
- Real-time SQL validation via LSP
- SQL syntax highlighting with comprehensive TextMate grammar
- SQL formatting with customizable options
- Intelligent autocomplete for SQL keywords and functions
- Hover documentation for SQL keywords
- Multi-dialect support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)

#### Commands
- GoSQLX: Validate SQL
- GoSQLX: Format SQL
- GoSQLX: Analyze SQL
- GoSQLX: Restart Language Server

#### Settings
- `gosqlx.enable`: Enable/disable language server
- `gosqlx.executablePath`: Path to gosqlx binary
- `gosqlx.format.indentSize`: Formatting indent size
- `gosqlx.format.uppercaseKeywords`: Uppercase SQL keywords
- `gosqlx.dialect`: SQL dialect selection

---

### Added - SQL Standards Compliance (PRs #124-#126)

#### Token Type Unification (ARCH-002, PR #124)
- **120+ new SQL token types** with proper categorization
- Helper methods: `IsKeyword()`, `IsOperator()`, `IsLiteral()`, `IsDMLKeyword()`, `IsDDLKeyword()`, `IsJoinKeyword()`, `IsWindowKeyword()`, `IsAggregateFunction()`, `IsDataType()`, `IsConstraint()`, `IsSetOperation()`
- ModelType field for O(1) int-based comparisons
- **14x faster** token type checking (0.28ns vs 4.9ns)
- Token range constants for category boundaries

#### FETCH FIRST / OFFSET-FETCH (SQL-99 F861, F862, PR #125)
- `FETCH FIRST n ROWS ONLY` / `FETCH NEXT n ROWS ONLY`
- `FETCH FIRST n ROWS WITH TIES` (preserves ties in sort order)
- `FETCH FIRST n PERCENT ROWS ONLY` (percentage-based limiting)
- `OFFSET n ROWS` combined with FETCH clause
- Added `FetchClause` AST node

#### TRUNCATE TABLE (SQL:2008, PR #126)
- Basic syntax: `TRUNCATE [TABLE] table_name`
- Multiple tables: `TRUNCATE TABLE t1, t2, t3`
- Identity behavior: `RESTART IDENTITY` / `CONTINUE IDENTITY`
- Cascade behavior: `CASCADE` / `RESTRICT`
- Added `TruncateStatement` AST node

#### MATERIALIZED CTE Support (PR #129)
- `WITH cte AS MATERIALIZED (...)` syntax
- `WITH cte AS NOT MATERIALIZED (...)` syntax
- PostgreSQL-compatible optimization hints

---

### Added - Parser Enhancements (PRs #162-#164, #176)

#### Column Constraints (PR #163, #146)
- Column constraints: PRIMARY KEY, NOT NULL, NULL, UNIQUE, DEFAULT, CHECK, REFERENCES, AUTO_INCREMENT
- Table-level constraints: PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK with CONSTRAINT name
- Parameterized types: VARCHAR(100), DECIMAL(10,2), CHAR(50)
- Referential actions: ON DELETE/UPDATE CASCADE, SET NULL, SET DEFAULT, RESTRICT, NO ACTION

#### Derived Tables / Subqueries in FROM (#148, PR #163)
- `(SELECT ...) AS alias` in FROM clause
- Support in JOIN clauses
- Full nested subquery support

#### Column Aliases with AS Keyword (#160, PR #163)
- Added `AliasedExpression` AST type
- Preserves `AS` keyword in formatted output

#### Function Calls in INSERT VALUES (#158, PR #163)
- NOW(), UUID(), CONCAT(), arithmetic expressions in VALUES
- Expression-based VALUES parsing

#### Parser Bug Fixes (PR #162)
- **#142** DISTINCT/ALL keyword support in SELECT
- **#143** Arithmetic expression operator precedence (+, -, *, /, %)
- **#144** SQL comments: line (`--`) and block (`/* */`)
- **#145** Double-quoted identifiers: `"column_name"`
- **#147** NATURAL JOIN, NATURAL LEFT/RIGHT JOIN
- **#150** String literal quoting with single quotes
- **#151** IS NULL / IS NOT NULL formatting
- **#152** BETWEEN expression formatting
- **#153** IN expression formatting
- **#157** Qualified asterisk: `table.*` syntax

---

### Added - Linter Rules (PRs #164, #176)

#### 10 Complete Lint Rules
| Rule | Name | Description | Auto-Fix |
|------|------|-------------|----------|
| L001 | Trailing Whitespace | Detects trailing whitespace | Yes |
| L002 | Mixed Tabs/Spaces | Detects mixed indentation | No |
| L003 | Consecutive Blank Lines | Detects multiple blank lines | Yes |
| L004 | Indentation Depth | Warns on excessive nesting (>4 levels) | No |
| L005 | Line Length | Warns on long lines | No |
| L006 | Column Alignment | Checks SELECT column alignment | No |
| L007 | Keyword Case | Enforces uppercase/lowercase keywords | Yes |
| L008 | Comma Placement | Trailing vs leading comma style | No |
| L009 | Aliasing Consistency | Detects mixed table aliasing | No |
| L010 | Redundant Whitespace | Finds multiple consecutive spaces | Yes |

---

### Added - Security Scanner (PRs #164, #176)

#### CLI Integration (#154)
- Integrated `pkg/sql/security` scanner into CLI analyzer
- Security score adjustments based on finding severity
- 100% detection rate on injection patterns

#### Detection Patterns
- Tautology patterns (`'1'='1'`, `OR 1=1`)
- UNION-based injection
- Time-based blind injection (SLEEP, WAITFOR DELAY)
- Comment bypass (`--`, `/**/`)
- Stacked queries
- Dangerous functions (xp_cmdshell, LOAD_FILE)

---

### Added - Developer Tools (PRs #131, #133, #136)

#### go-task Build System (PR #131)
- Replaced Makefile with comprehensive Taskfile.yml (420+ lines)
- 45+ tasks vs original 10 Makefile targets
- Task namespacing: `build:cli`, `test:race`, `lint:fix`
- Cross-platform builds (linux, darwin, windows / amd64, arm64)
- CPU and memory profiling support
- Fuzz testing integration
- Security scanning (govulncheck)
- Development watch mode

#### Structured Error Codes (PR #133)
- Tokenizer errors: E1001-E1005
- Parser errors: E2001-E2012
- Semantic errors: E3001-E3004 (UndefinedTable, UndefinedColumn, TypeMismatch, AmbiguousColumn)
- All errors include: error codes, location info, helpful hints, doc links
- CLI JSON output includes `Code` field

#### Unified Configuration Package (PR #133)
- `pkg/config/` with Config struct
- File and environment loaders
- LSP integration
- 78.6% test coverage

#### Caching System (PR #136)
- Keyword suggestion cache: **575x speedup** (12.87ns vs 7402ns)
- Config file cache: **22.5x speedup** (1302ns vs 29379ns)
- Thread-safe with RWMutex
- Automatic invalidation on file modification

---

### Added - Metrics & Monitoring (PR #129)

#### Comprehensive Metrics System
- Parser operation metrics (duration, errors, statement counts)
- AST pool metrics (gets/puts/balance)
- Statement pool metrics
- Expression pool metrics
- Tokenizer pool metrics with hit rate tracking
- Thread-safe atomic counters

---

### Added - Test Coverage (PRs #137, #138)

#### AST Test Coverage to 80%+ (PR #138)
- DateTimeField.String() covering 44+ cases
- Parser position tracking infrastructure
- `ParseWithPositions()` method for position-aware parsing
- `currentLocation()` helper for accurate error locations

#### AST Interface Tests (PR #137)
- statementNode() marker methods for all statements
- expressionNode() marker methods for all expressions
- TokenLiteral() for 60+ node types
- Children() with comprehensive branch coverage
- Coverage improved from 60.7% to 70.1%

---

### Improved

#### Performance Optimizations (PR #127)
- O(1) switch dispatch on ModelType instead of O(n) isAnyType() calls
- isComparisonOperator() helper with O(1) ModelType switch
- Buffer pooling for keyword conversion (sync.Pool)
- ASCII fast-path in skipWhitespace for >99% of cases
- Parser pooling: GetParser/PutParser via sync.Pool
- CPU-scaled sustained load tests

#### AST Pool Architecture (PR #129)
- Iterative cleanup with work queue pattern to prevent stack overflow
- Added 8 new expression pools (Exists, Any, All, List, Unary, Extract, Position, Substring)
- MaxCleanupDepth and MaxWorkQueueSize limits

#### Type Assertion Safety (PR #129)
- Added proper `ok` pattern checking in `alter.go` and `value.go`

#### Race Condition Fixes (PR #129)
- Fixed data races in metrics.go using atomic operations
- Fixed race condition in LSP documents.go with defensive copy
- Fixed race condition in watch.go with RWMutex protection

#### Documentation Cleanup (PR #141)
- Deleted 4 LLM-generated files (~1,725 lines)
- Fixed API_REFERENCE.md return types
- Added 10 missing error codes to ERROR_CODES.md
- Fixed 50+ broken links and inaccurate references

---

### Changed

#### Go Version Update (PR #140)
- Minimum requirement: Go 1.21+ (was 1.19)
- Toolchain: Go 1.21+
- Updated all CI/CD workflows to test against Go 1.21+
- golangci-lint upgraded to v2.6.2

#### CLI Output Improvements (PR #163)
- Output file flag (`-o`) now functional for lint and analyze commands
- MERGE statement formatter with full clause support

---

### Fixed

- Critical type assertion panics in ALTER and VALUE parsing (PR #129)
- Race conditions in concurrent document management (PR #129)
- LSP hover returning nil instead of empty response (PR #129)
- Tokenizer negative column numbers in toSQLPosition (PR #129)
- L004 indentation depth display for depth > 9 (PR #164)
- CAST keyword missing from tokenizer keywordTokenTypes map (PR #176)
- || operator test with correct TokenTypeSingleQuotedString (PR #176)

---

### Known Issues (Future Enhancements)

The following features were identified during real-world testing and are tracked for future releases:
- **#178**: PostgreSQL JSONB existence operators (?, ?|, ?&) in parser
- **#179**: Multi-row INSERT VALUES syntax
- **#180**: BETWEEN with complex expression bounds
- **#181**: Tuple expressions in IN clause
- **#182**: PostgreSQL ARRAY constructor syntax
- **#183**: WITHIN GROUP ordered set aggregates

## [1.5.1] - 2025-11-15 - Phases 2-3 Test Coverage Completion

### Phase 3 Complete: Token and Tokenizer Coverage Enhancement

**Released - PR #88**

#### Test Coverage Enhancement - Phase 3 (Token, Tokenizer)
- **Comprehensive Test Suite**: Added 2 new test files with 378 lines of test code
- **Perfect Token Coverage Achieved**: Token package reaches 100% coverage ⭐
- **Coverage Achievements**:
  - Token Package: 59.1% → **100.0%** (+40.9%) - **Perfect Coverage!**
  - Tokenizer Package: 69.1% → **76.1%** (+7.0%) - **Target Exceeded!**
- **Zero Race Conditions**: All tests pass with race detection enabled

#### New Test Files Created - Phase 3
- **pkg/sql/token/coverage_enhancement_test.go** (332 lines)
  - IsKeyword(), IsOperator(), IsLiteral() - all classification methods
  - 95+ subtests covering all token types (25 keywords, 7 operators, 6 literals)
  - Edge cases: empty types, custom tokens, case sensitivity
  - Token alias testing: EQ/EQUAL, NEQ/NOT_EQ
  - Method combinations: TRUE/FALSE as both keywords and literals
- **pkg/sql/tokenizer/coverage_enhancement_test.go** (310 lines)
  - Buffer pool operations (NewBufferPool, Get, Put, Grow)
  - Error handling (7 error creation and formatting functions)
  - Position tracking (Location, AdvanceN)
  - Tokenizer operations (NewWithKeywords, Reset)
  - 25+ subtests with comprehensive edge case coverage

#### Combined Phase 1 + Phase 2 + Phase 3 Impact
- **8 packages** with comprehensive coverage improvements
- **4,823 lines** of production-grade test code
- **3 packages at perfect 100% coverage**: Models, Keywords, Token
- **Zero race conditions** across entire codebase
- **Production-ready** reliability validated

---

### Phase 2 Complete: Keywords, Errors, and AST Coverage Enhancement

**Released - PR #87**

#### Test Coverage Enhancement - Phase 2 (Keywords, Errors, AST)
- **Comprehensive Test Suite**: Added 3 new test files with 1,351 lines of test code
- **Perfect Coverage Achieved**: Keywords package reaches 100% coverage
  - Keywords Package: 92.8% → **100.0%** (+7.2%) - Perfect Coverage
  - Errors Package: 83.8% → **95.6%** (+11.8%) - Exceeded Target
  - AST Package: 73.7% → **74.4%** (+0.7%) - Marker functions covered
- **Documentation Cleanup**: Removed 2,538 lines of obsolete/redundant documentation
- **Archived Historical Docs**: Moved outdated architecture docs to archive with explanation

#### New Test Files Created - Phase 2
- **pkg/sql/keywords/coverage_enhancement_test.go** (405 lines)
  - All 5 SQL dialects tested (Generic, MySQL, PostgreSQL, SQLite, Unknown)
  - Case-sensitive and case-insensitive mode coverage
  - Edge cases: empty strings, whitespace, special characters
  - 9 comprehensive test functions
- **pkg/sql/ast/marker_functions_test.go** (387 lines)
  - 14 statement types + 16 expression types + 4 ALTER operations
  - Interface compliance validation
  - Edge cases with zero-value structs
  - 5 test functions with 50+ subtests
- **pkg/errors/coverage_enhancement_test.go** (559 lines)
  - 9 advanced error builder functions
  - 5 suggestion helper functions
  - Integration and edge case validation
  - 4 test suites with 50+ subtests

#### Documentation Improvements
- Removed 5 obsolete LLM-generated session summaries (2,538 lines)
- Archived 2 outdated architecture/performance docs
- Created `PHASE2_COVERAGE_SUMMARY.md` with comprehensive documentation
- Added `archive/historical-architecture-docs/README.md` to explain historical context

#### Combined Phase 1 + Phase 2 Impact
- **6 packages** with comprehensive coverage improvements
- **4,445 lines** of production-grade test code

## [1.5.0] - 2025-11-15 - Phase 1 Test Coverage Achievement

### Phase 1 Complete: Comprehensive Test Coverage Across CLI, Parser, and Tokenizer

**This release marks a major milestone** in GoSQLX quality assurance with comprehensive test coverage improvements across three critical packages. All Phase 1 coverage targets have been met or exceeded, establishing GoSQLX as production-grade software with extensive test validation.

### Test Coverage Enhancement - Phase 1 Complete (CLI, Parser, Tokenizer)
- **Comprehensive Test Suite**: Added 7 new test files with 3,094 lines of test code
- **Triple Coverage Achievement**: Met or exceeded all three coverage targets
  - CLI Package: 63.3% coverage (exceeded 60% target by 3.3%)
  - Parser Package: 75.0% coverage (met 75% target exactly)
  - Tokenizer Package: 76.5% coverage (exceeded 70% target by 6.5%)
- **CLI Code Refactoring**: Improved maintainability with net reduction of 529 lines
- **Real-World Integration Testing**: 115+ production SQL queries validated across multiple dialects
- **Quality Assurance**: All tests pass with race detection enabled, zero race conditions detected

### New Test Files Created - Parser Package
- **parser_additional_coverage_test.go** (420 lines): Additional statement coverage (CTEs, window functions)
- **parser_edge_cases_test.go** (450 lines): Edge cases and boundary conditions
- **parser_error_recovery_test.go** (380 lines): Error recovery and handling
- **parser_final_coverage_test.go** (350 lines): Final coverage gap filling
- **parser_targeted_coverage_test.go** (410 lines): Targeted function coverage improvements
- **error_recovery_test.go** (61 lines): Error recovery integration tests
- **integration_test.go** (311 lines): Real-world SQL query validation framework

### New Test Files Created - Tokenizer Package
- **tokenizer_coverage_test.go** (712 lines): Comprehensive tokenizer feature testing
  - Backtick identifiers (MySQL-style)
  - Triple-quoted strings (Python-style)
  - Escape sequences (\n, \t, \r, \\, \', \")
  - Scientific notation (1.23e4, 1.23E+4)
  - UTF-8 multi-byte characters (Chinese, Japanese, Korean, Arabic, emoji)
  - Operators and punctuation
  - Custom keyword support
  - Debug logger functionality

### Enhanced CLI Testing
- **sql_analyzer_test.go** (318 lines): Comprehensive CLI command testing
  - Analyze, validate, format, parse command coverage
  - Edge case testing: empty files, large files, invalid SQL, UTF-8
  - Error handling validation across all commands
  - Input detection testing (file vs SQL string)

### Integration Test Infrastructure
- **testdata/postgresql/queries.sql**: PostgreSQL-specific queries
- **testdata/mysql/queries.sql**: MySQL-specific queries
- **testdata/real_world/ecommerce.sql**: Complex e-commerce queries
- 115+ real-world SQL queries from production workloads
- Multi-dialect support validation
- Success rate tracking and failure analysis

### Coverage Progression
| Component | Initial | Target | Achieved | Status |
|-----------|---------|--------|----------|--------|
| CLI | ~50% | 60% | **63.3%** | ✅ Exceeded by 3.3% |
| Parser | 57.4% | 75% | **75.0%** | ✅ Met exactly |
| Tokenizer | 60.0% | 70% | **76.5%** | ✅ Exceeded by 6.5% |

### Function-Level Improvements - Tokenizer
| Function | Initial | Final | Improvement |
|----------|---------|-------|-------------|
| handleEscapeSequence | 0.0% | **85.7%** | +85.7% |
| readTripleQuotedString | 0.0% | **96.4%** | +96.4% |
| readBacktickIdentifier | 0.0% | **100%** | +100% (full coverage!) |
| SetDebugLogger | 0.0% | **100%** | +100% (full coverage!) |
| readPunctuation | 70.2% | **92.3%** | +22.1% |
| readQuotedIdentifier | 77.8% | **96.3%** | +18.5% |
| readNumber | 77.6% | **85.7%** | +8.1% |
| TokenizeContext | 81.1% | **84.9%** | +3.8% |

### CLI Code Refactoring
- **analyze.go**: Improved error handling consistency
- **config.go**: Enhanced configuration management
- **format.go**: Better error messages and UTF-8 handling
- **input_utils.go**: Consolidated input reading logic
- **parse.go**: Improved output formatting
- **validate.go**: Enhanced validation error reporting
- **Net Impact**: -529 lines with improved maintainability

### Testing Approach
- Table-driven test design with comprehensive subtests
- Short mode support for fast pre-commit hooks
- Integration tests document parser limitations for future improvements
- UTF-8 internationalization testing (8 languages tested)
- Edge case validation across all components
- Race detection validated confirming thread safety

### Quality Metrics
- ✅ All tests pass with race detection enabled (go test -race)
- ✅ Pre-commit hook integration with short mode support
- ✅ Code formatted with go fmt
- ✅ No issues reported by go vet
- ✅ Thread-safe operation confirmed across all test scenarios
- ✅ Real-world SQL validation: 95%+ success rate on production queries

### Impact

**Production Confidence**: This Phase 1 test coverage enhancement establishes GoSQLX as enterprise-grade software with:
- **Comprehensive Validation**: 3,094 lines of new tests covering real-world usage patterns
- **International Compliance**: Full UTF-8 support validated across 8 languages
- **Thread-Safe Operation**: Zero race conditions detected in 20,000+ concurrent operations
- **Real-World Readiness**: 95%+ success rate on production SQL queries
- **Code Quality**: 529 lines removed through refactoring, improving maintainability
- **Performance Maintained**: 1.38M+ ops/sec sustained throughout all test scenarios

This release positions GoSQLX as the most thoroughly tested Go SQL parser library, with comprehensive test coverage exceeding industry standards across all critical components.

### Related Pull Request

**PR #85**: [Phase 1 Test Coverage Achievement - CLI, Parser, and Tokenizer](https://github.com/ajitpratap0/GoSQLX/pull/85)
- 81 files changed, 25,883 insertions, 1,735 deletions
- 20 commits including 8 CI/CD fix commits
- All 16 CI checks passing (tests across 3 platforms × 3 Go versions, linting, security, benchmarks)
- Comprehensive review and validation

### Documentation Created
- **CLI_REFACTORING_SUMMARY.md**: CLI coverage and refactoring details
- **PARSER_COVERAGE_SUMMARY.md**: Parser test coverage breakdown
- **TOKENIZER_COVERAGE_SUMMARY.md**: Tokenizer coverage achievement details
- **SESSION_PROGRESS_SUMMARY.md**: Overall session progress tracking

### Key Improvements

**Production Readiness Enhancements:**
- **Battle-Tested Reliability**: 3,094 lines of new test code across 7 comprehensive test files
- **Real-World Validation**: 115+ production SQL queries tested across multiple database dialects (PostgreSQL, MySQL, SQL Server, Oracle)
- **International Support**: Full UTF-8 testing across 8 languages (Chinese, Japanese, Korean, Arabic, Russian, Spanish, French, German)
- **Thread Safety**: All tests pass with race detection enabled, zero race conditions detected across 20,000+ concurrent operations
- **Performance Validated**: 95%+ success rate on real-world SQL queries with maintained throughput (1.38M+ ops/sec)

**Code Quality Improvements:**
- **CLI Refactoring**: Net reduction of 529 lines through improved architecture and code consolidation
- **Enhanced Error Handling**: Better error messages and UTF-8 handling across all CLI commands
- **Improved Maintainability**: Consolidated input reading logic and consistent validation patterns

**Testing Infrastructure:**
- **Short Mode Support**: Fast pre-commit hook integration for developer productivity
- **Integration Testing**: Real-world SQL validation framework with success rate tracking
- **Edge Case Coverage**: Comprehensive testing of boundary conditions, empty inputs, and invalid syntax
- **Resource Management**: Proper object pooling validated in all test scenarios

### Complete Coverage Breakdown

**Before Phase 1:**
- CLI Package: ~50% coverage
- Parser Package: 57.4% coverage
- Tokenizer Package: 60.0% coverage

**After Phase 1:**
- **CLI Package**: 63.3% coverage ⬆️ **+13.3%** (exceeded 60% target)
- **Parser Package**: 75.0% coverage ⬆️ **+17.6%** (met 75% target exactly)
- **Tokenizer Package**: 76.5% coverage ⬆️ **+16.5%** (exceeded 70% target)

### Previous Test Coverage Enhancement - AST Package (v1.4.0)
- **Comprehensive Test Suite**: Added 10 new test files with ~1,800 lines of tests
- **Coverage Improvement**: Increased AST package coverage from 59.6% to 73.4% (+13.8 percentage points)
- **Production Confidence**: Exceeded 70% coverage target, validating production readiness

### New Test Files Created
- **data_loading_test.go** (~250 lines): Cloud data loading features (StageParamsObject, DataLoadingOptions, helpers)
- **pool_test.go** (~180 lines): Object pooling infrastructure (Insert/Update/Delete statement pools, reuse validation)
- **span_test.go** (~450 lines): Source location tracking (SpannedNode, UnionSpans, all Span() methods)
- **alter_test.go** (~650 lines): ALTER statements (Table/Role/Policy/Connector operations, RoleOption methods)
- **dml_test.go**: Data Manipulation Language statement tests
- **data_type_test.go**: SQL data type handling tests
- **nodes_test.go** (~300 lines): AST node interfaces (marker methods, TokenLiteral(), Children())
- **operator_test.go**: Operator types and operations tests
- **types_test.go**: AST type definition tests

### Enhanced Existing Tests
- **value_test.go** (+180 lines): Added comprehensive Value.String() tests for 11 missing types (byte strings, raw strings, national/hex/double-quoted strings), plus all 40+ DateTimeField variants
- **trigger_test.go**: Applied go fmt formatting for code consistency

### Coverage Progression
| Stage | Coverage | Gain | Test File |
|-------|----------|------|-----------|
| Initial | 59.6% | - | Baseline |
| Data loading tests | 63.1% | +3.5% | data_loading_test.go |
| Pool tests | 67.7% | +4.6% | pool_test.go |
| Span tests | 72.3% | +4.6% | span_test.go |
| Value enhancements | 73.4% | +1.1% | value_test.go |
| **Final** | **73.4%** | **+13.8%** | **Total** |

### Testing Approach
- Table-driven test design with subtests for comprehensive coverage
- Edge case validation across all AST node types
- Race detection validated (go test -race) confirming thread safety
- Memory-efficient pool testing with reuse verification
- Source location tracking validation for error reporting

### Quality Metrics
- ✅ All tests pass with race detection enabled
- ✅ Code formatted with go fmt
- ✅ No issues reported by go vet
- ✅ Thread-safe operation confirmed across all test scenarios
- ✅ Production-ready reliability validated for enterprise SQL parsing

### Impact
This substantial test coverage increase provides strong confidence in the AST package's correctness, thread safety, and production readiness. The comprehensive test suite validates complex SQL parsing scenarios including JOINs, CTEs, window functions, and advanced DML/DDL operations.

## [1.4.0] - 2025-09-07 - CLI Release and Code Quality

### ✅ CLI Production Release
- **Complete CLI Tool Suite**: Production-ready CLI with validate, format, analyze, and parse commands
- **High-Performance CLI**: 1.38M+ operations/second validation, 2,600+ files/second formatting throughput
- **Robust Input Detection**: Intelligent file vs SQL detection using `os.Stat()` with security limits (10MB max)
- **Memory Leak Prevention**: Fixed critical memory leak in format command with proper AST cleanup patterns
- **Comprehensive Testing**: Added benchmark tests, integration tests, and CLI command tests
- **Error Handling**: Enhanced error messages with file access validation and context

### ✅ CLI Features
- **Multi-format Output**: Support for JSON, YAML, table, and tree output formats
- **Batch Processing**: Directory expansion and glob pattern support for processing multiple SQL files
- **Security Limits**: File size validation, extension checking, and input sanitization
- **CI/CD Integration**: Format checking mode with proper exit codes for continuous integration
- **Performance Benchmarking**: Comprehensive benchmark suite validating CLI performance claims

### 🚀 Performance & Quality  
- **Token Conversion Performance**: TokenType.String() method optimized with comprehensive hash map (90+ token types)
- **Code Reduction**: analyze.go reduced from 570 to 218 lines (-62%) through legacy code elimination
- **Static Analysis**: All go vet, go fmt, and linting issues resolved
- **Test Reliability**: Benchmark error handling corrected for concurrent test execution

### 🔧 Technical Implementation
- **TokenType String Mapping**: Complete hash map implementation covering all 90+ token types vs previous 24 cases
- **Legacy Type System Removal**: Eliminated `AnalysisResult` type and `convertAnalysisReport()` function overhead
- **Modern CLI Architecture**: Unified analysis system using only modern `AnalysisReport` types
- **Benchmark Corrections**: Fixed goroutine error handling in scalability_bench_test.go and comprehensive_bench_test.go

### 📚 Documentation Updates
- **FIXES_APPLIED.md**: Comprehensive documentation of all code quality improvements applied
- **Session tracking**: Detailed before/after comparisons and impact metrics for all optimizations
- **CLI usage patterns**: Updated examples reflecting enhanced command functionality

### 🔄 Backward Compatibility
- **100% functional compatibility**: All CLI commands maintain identical user-facing behavior  
- **API preservation**: No breaking changes to public interfaces or command-line arguments
- **Performance maintained**: All existing functionality performs at same or better speed

### Goals Achieved
- ✅ CLI command modernization and optimization
- ✅ Significant code reduction through legacy elimination (-350+ lines)  
- ✅ Performance optimization of core token conversion operations
- ✅ Complete static analysis compliance (go vet, go fmt clean)
- ✅ Enhanced test reliability and benchmark correctness

## [1.3.0] - 2025-09-04 - Phase 2.5: Window Functions

### ✅ Major Features Implemented
- **Complete Window Function Support**: Full SQL-99 compliant window function parsing with OVER clause
- **PARTITION BY and ORDER BY**: Complete window specification support with expression parsing
- **Window Frame Clauses**: ROWS and RANGE frame specifications with proper bounds (UNBOUNDED PRECEDING/FOLLOWING, CURRENT ROW)
- **Ranking Functions**: ROW_NUMBER(), RANK(), DENSE_RANK(), NTILE() with full integration
- **Analytic Functions**: LAG(), LEAD(), FIRST_VALUE(), LAST_VALUE() with offset and default value support
- **Function Call Enhancement**: Complete function call parsing with parentheses, arguments, and DISTINCT support
- **Enhanced Expression Parsing**: Upgraded parseExpression() to handle complex function calls and window specifications

### 🚀 Performance & Quality
- **1M+ operations/second** sustained throughput maintained (up to 1.38M peak with concurrency)
- **Zero performance regression** - all existing functionality performs at same speed
- **Race-free implementation** - comprehensive concurrent testing validates thread safety
- **Memory efficient** - object pooling preserved with 60-80% memory reduction
- **Production-grade reliability** - extensive load testing and memory leak detection

### 🎯 SQL Standards Compliance
- **~80-85% SQL-99 compliance** achieved (significant advancement from ~70% SQL-92 in v1.2.0)
- **Complete window function standard** implemented per SQL-99 specification
- **Advanced analytical capabilities** - full support for ranking and analytic window functions
- **Complex query compositions** - window functions integrated with CTEs and set operations from previous phases

### 🔧 Technical Implementation
- **parseFunctionCall()** - Complete function call parsing with OVER clause detection and window specification handling
- **parseWindowSpec()** - Window specification parsing with PARTITION BY, ORDER BY, and frame clause support
- **parseWindowFrame()** - Frame clause parsing with ROWS/RANGE and bound specifications (UNBOUNDED, CURRENT ROW)
- **parseFrameBound()** - Individual frame bound parsing with expression support for offset values
- **Enhanced parseExpression()** - Function call detection and routing to window function parsing
- **Updated parseSelectStatement()** - Integrated enhanced expression parsing for SELECT column lists

### 📊 Comprehensive Testing
- **6 comprehensive test functions** with 14 total test cases covering all window function scenarios
- **Basic window functions**: ROW_NUMBER() OVER (ORDER BY column)
- **Partitioned window functions**: RANK() OVER (PARTITION BY dept ORDER BY salary DESC)
- **Frame specifications**: SUM(column) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)
- **Complex compositions**: Multiple window functions in single queries with various specifications
- **100% test pass rate** with race detection enabled
- **Extensive error case coverage** with contextual error messages

### 📚 Documentation Updates
- **Enhanced parser package documentation** with Phase 2.5 examples and window function API references
- **Updated AST package documentation** with window function node descriptions
- **Enhanced keywords package documentation** for window function keyword support
- **Comprehensive function documentation** with usage examples for all new parsing methods

### 🔄 Backward Compatibility
- **100% backward compatible** - all existing functionality preserved without changes
- **API stability** - no breaking changes to public interfaces or method signatures
- **Legacy test compatibility** - all Phase 1, Phase 2, and prior tests continue passing
- **Performance maintained** - no degradation in existing query parsing performance

### Goals Achieved
- ✅ ~80-85% SQL-99 compliance milestone reached
- ✅ Production-grade window function implementation with complete SQL-99 feature set
- ✅ Enhanced parser architecture supporting complex function calls and specifications
- ✅ Comprehensive test coverage for all window function categories
- ✅ Zero performance regression while adding significant new functionality
- ✅ Complete integration with existing CTE and set operations from previous phases

## [1.2.0] - 2025-09-04 - Phase 2: Advanced SQL Features

### ✅ Major Features Implemented
- **Complete Common Table Expression (CTE) support**: Simple and recursive CTEs with full SQL-92 compliance
- **Set operations**: UNION, UNION ALL, EXCEPT, INTERSECT with proper left-associative parsing
- **Multiple CTE definitions**: Comma-separated CTEs in single query with column specifications
- **CTE Integration**: Full compatibility with all statement types (SELECT, INSERT, UPDATE, DELETE)
- **Enhanced parser architecture**: New parsing functions for WITH statements and set operations

### 🚀 Performance & Quality
- **946K+ sustained operations/second** (30s load testing) - production grade performance
- **1.25M+ operations/second** peak throughput with concurrent processing
- **<1μs latency** for complex queries with CTEs and set operations
- **Zero performance regression** from Phase 1 - all existing functionality maintained

### 🎯 SQL Standards Compliance
- **~70% SQL-92 compliance** achieved (up from ~40% in Phase 1)
- **Advanced SQL features**: WITH clause, RECURSIVE support, set operations
- **Complex query compositions**: CTEs combined with set operations in single queries
- **Proper operator precedence**: Left-associative parsing for chained set operations

### 🔧 Technical Implementation
- **parseWithStatement()** - Complete WITH clause parsing with recursive support
- **parseSelectWithSetOperations()** - Set operations parsing with proper precedence  
- **parseCommonTableExpr()** - Individual CTE parsing with column specifications
- **parseMainStatementAfterWith()** - Post-CTE statement routing with full integration
- **Enhanced AST structures** - Complete integration with existing AST framework

### 📊 Comprehensive Testing
- **24+ test functions** total (9 new Phase 2 tests added)
- **4 comprehensive CTE tests**: Simple CTE, Recursive CTE, Multiple CTEs, Column specs
- **5 comprehensive set operation tests**: All operations, chaining, CTE combinations

### 📚 Documentation Updates
- **Enhanced Go package documentation** with Phase 2 examples and API references
- **Comprehensive README updates** with CTE and set operations examples
- **Updated performance benchmarks** reflecting Phase 2 capabilities
- **Complete API documentation** for all new parsing functions

### 🔄 Backward Compatibility
- **100% backward compatible** - all existing functionality preserved
- **API stability** - no breaking changes to public interfaces
- **Legacy test compatibility** - all Phase 1 and prior tests continue passing

### Goals Achieved
- ✅ ~70% SQL-92 compliance milestone reached
- ✅ Production-grade CTE implementation with recursive support
- ✅ Complete set operations support with proper precedence
- ✅ Enhanced error handling with contextual messages
- ✅ Comprehensive test coverage for all new features
- ✅ Zero performance regression while adding major features

## [1.1.0] - 2025-09-03 - Phase 1: Core SQL Enhancements

### ✅ Implemented Features  
- **Complete JOIN support**: All JOIN types (INNER/LEFT/RIGHT/FULL OUTER/CROSS/NATURAL)
- **Proper join tree logic**: Left-associative join relationships with synthetic table references
- **USING clause support**: Single-column USING clause parsing (multi-column planned for Phase 2)
- **Enhanced error handling**: Contextual error messages for JOIN parsing
- **Comprehensive test coverage**: 15+ JOIN test scenarios including error cases
- **Race-free implementation**: Zero race conditions detected in concurrent testing

### 🏗️ Foundation Laid (Phase 2 Ready)
- **CTE AST structures**: WithClause and CommonTableExpr defined with TODO integration points
- **Token support**: Added WITH, RECURSIVE, UNION, EXCEPT, INTERSECT keywords
- **Parser hooks**: Integration points documented for Phase 2 CTE completion

### Goals
- Achieve 70% SQL-92 compliance
- Unified AST structure
- Consistent error system with context and hints

## [1.0.2] - 2025-08-23

### Added
- Comprehensive Go package documentation for all major packages
- Root-level doc.go file with module overview and usage examples
- Package-level documentation comments for proper pkg.go.dev indexing
- Performance metrics and feature highlights in documentation

### Improved
- Documentation quality for better developer experience
- Module discoverability on pkg.go.dev

## [1.0.1] - 2025-08-23

### Added
- Performance monitoring package (`pkg/sql/monitor`) for real-time metrics
- Metrics collection for tokenizer, parser, and pool operations
- Performance summary generation with throughput calculations
- Thread-safe concurrent metrics recording
- Configurable metrics enable/disable functionality
- GitHub issue templates for bug reports, feature requests, and performance issues
- Pull request template with comprehensive checklist
- Enhanced README with community badges and widgets
- Project metrics and star history visualization

### Fixed
- Parser now correctly handles multiple JOIN clauses in complex queries
- Resolved race conditions in monitor package with atomic operations
- Fixed mutex copy issues in metrics collection
- Added missing EOF tokens in benchmark tests
- Fixed Windows test compatibility issues
- Resolved all golangci-lint warnings and ineffectual assignments
- Fixed staticcheck U1000 warnings for unused code

### Improved
- Enhanced performance tracking capabilities
- Better observability for production deployments
- Real-time performance monitoring support
- CI/CD pipeline now fully green across all platforms (Linux, macOS, Windows)
- Test coverage for monitor package at 98.6%
- All workflows (Go, Lint, Tests) passing with Go 1.19, 1.20, and 1.21

## [1.0.0] - 2024-12-01

### Added
- Production-ready SQL parsing with zero-copy tokenization
- Object pooling system for 60-80% memory reduction
- Multi-dialect SQL support (PostgreSQL, MySQL, SQL Server, Oracle, SQLite)
- MySQL backtick identifier support
- Full Unicode/UTF-8 support for international SQL
- Comprehensive test suite with race condition detection
- Performance benchmarking suite
- Real-world SQL query validation (115+ queries)
- Thread-safe implementation with linear scaling to 128+ cores
- AST (Abstract Syntax Tree) generation from tokens
- Visitor pattern support for AST traversal
- Position tracking with line/column information
- Detailed error reporting with context

### Changed
- Improved tokenizer performance by 47% over v0.9.0
- Enhanced token processing speed to 8M tokens/sec
- Reduced memory allocations through intelligent pooling
- Updated token type system to prevent collisions
- Refactored parser for better maintainability

### Fixed
- Token type collisions in constant definitions
- Race conditions in concurrent usage
- Memory leaks in long-running operations
- Test compatibility issues with hardcoded expectations
- Import path inconsistencies in examples

### Performance
- **Throughput**: 2.2M operations/second
- **Token Processing**: 8M tokens/second
- **Latency**: < 200ns for simple queries
- **Memory**: 60-80% reduction with pooling
- **Concurrency**: Linear scaling to 128 cores
- **Race-free**: 0 race conditions detected

### Tested
- 20,000+ concurrent operations
- 115+ real-world SQL queries
- 8 international languages
- Extended load testing (30+ seconds)
- Memory leak detection

### Upgrade Guide (0.9.0 to 1.0.0)

1. **Token Type Changes**: Review any code that directly references token type constants
2. **Pool Usage**: Always use `defer` when returning objects to pools
3. **Import Paths**: Update imports from test packages if used
4. **Performance**: Expect 47% performance improvement, adjust timeouts accordingly

For the fuller guide, see [Upgrading to v1.0.0 from v0.9.0](https://github.com/ajitpratap0/GoSQLX/blob/main/docs/UPGRADE_GUIDE.md) in `docs/UPGRADE_GUIDE.md`.

### Breaking Changes in 1.0.0

- Token type constants have been reorganized to prevent collisions
- Some internal APIs have been refactored for better performance
- Test helper functions have been updated

## [0.9.0] - 2024-01-15

### Added
- Initial release of GoSQLX
- Basic SQL tokenization
- Simple parser implementation
- Core AST node types
- Keyword recognition
- Basic error handling

### Known Issues
- Limited concurrency support
- Higher memory usage
- Token type collisions
- Limited SQL dialect support

## [0.8.0] - 2023-12-01 [Pre-release]

### Added
- Prototype tokenizer
- Basic SQL parsing
- Initial AST structure

---

## Version History Summary

| Version | Release Date | Status | Key Features |
|---------|--------------|--------|--------------|
| 1.9.0 | 2026-02-28 | Current | SQLite PRAGMA, tautology detection, 19 post-UAT fixes, lint CI-gate |
| 1.8.0 | 2026-02-24 | Previous | Dialect engine, MySQL support, Query Transform API, WASM, Token type overhaul |
| 1.7.0 | 2026-02-12 | Previous | Schema-qualified names, Parser Batches 5-8, quoted identifiers fix |
| 1.6.0 | 2025-12-09 | Previous | PostgreSQL Extensions, LSP Server, VSCode Extension, 14x faster tokens |
| 1.5.0 | 2025-11-15 | Stable | Phase 1 Test Coverage: CLI 63.3%, Parser 75%, Tokenizer 76.5% |
| 1.4.0 | 2025-09-07 | Previous | Production CLI, high-performance commands, memory leak fixes |
| 1.3.0 | 2025-09-04 | Stable | Window functions, ~80-85% SQL-99 compliance |
| 1.2.0 | 2025-09-04 | Previous | CTEs, set operations, ~70% SQL-92 compliance |
| 1.1.0 | 2025-01-03 | Previous | Complete JOIN support, enhanced error handling |
| 1.0.0 | 2024-12-01 | Stable | Production ready, +47% performance |
| 0.9.0 | 2024-01-15 | Legacy | Initial public release |
| 0.8.0 | 2023-12-01 | Pre-release | Prototype version |

## Support

For questions about upgrading or changelog entries:
- Open an issue: https://github.com/ajitpratap0/GoSQLX/issues
- Join discussions: https://github.com/ajitpratap0/GoSQLX/discussions

[Unreleased]: https://github.com/ajitpratap0/GoSQLX/compare/v1.17.0...HEAD
[1.17.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.16.0...v1.17.0
[1.16.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.12.1...v1.13.0
[1.12.1]: https://github.com/ajitpratap0/GoSQLX/compare/v1.12.0...v1.12.1
[1.12.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.10.2...v1.12.0
[1.9.1]: https://github.com/ajitpratap0/GoSQLX/compare/v1.9.0...v1.9.1
[1.8.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/ajitpratap0/GoSQLX/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ajitpratap0/GoSQLX/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/ajitpratap0/GoSQLX/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/ajitpratap0/GoSQLX/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/ajitpratap0/GoSQLX/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/ajitpratap0/GoSQLX/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/ajitpratap0/GoSQLX/releases/tag/v0.8.0
