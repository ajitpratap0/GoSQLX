// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package models

// TokenType represents the type of a SQL token.
//
// TokenType is the core classification system for all lexical units in SQL.
// GoSQLX v1.6.0 supports 500+ distinct token types organized into logical
// ranges for efficient categorization and type checking.
//
// Token Type Organization:
//
//   - Special (0-9): EOF, UNKNOWN
//   - Basic (10-29): WORD, NUMBER, IDENTIFIER, PLACEHOLDER
//   - Strings (30-49): Various string literal formats
//   - Operators (50-149): Arithmetic, comparison, JSON/JSONB operators
//   - Keywords (200-499): SQL keywords by category
//   - Data Types (430-449): SQL data type keywords
//
// v1.6.0 PostgreSQL Extensions:
//
//   - JSON/JSONB Operators: ->, ->>, #>, #>>, @>, <@, #-, @?, @@, ?&, ?|
//   - LATERAL: Correlated subqueries in FROM clause
//   - RETURNING: Return modified rows from DML statements
//   - FILTER: Conditional aggregation in window functions
//   - DISTINCT ON: PostgreSQL-specific row selection
//
// Performance: TokenType is an int with O(1) lookup via range checking.
// All Is* methods use constant-time comparisons.
//
// Example usage:
//
//	// Check token category
//	if tokenType.IsKeyword() {
//	    // Handle SQL keyword
//	}
//	if tokenType.IsOperator() {
//	    // Handle operator (+, -, *, /, ->, etc.)
//	}
//
//	// Check specific categories
//	if tokenType.IsWindowKeyword() {
//	    // Handle OVER, PARTITION BY, ROWS, RANGE
//	}
//	if tokenType.IsDMLKeyword() {
//	    // Handle SELECT, INSERT, UPDATE, DELETE
//	}
//
//	// PostgreSQL JSON operators
//	switch tokenType {
//	case TokenTypeArrow:      // -> (JSON field access)
//	case TokenTypeLongArrow:  // ->> (JSON field as text)
//	    // Handle JSON operations
//	}
type TokenType int

// Token range constants for maintainability and clarity.
// These define the boundaries for each category of tokens.
const (
	// TokenRangeBasicStart marks the beginning of basic token types
	TokenRangeBasicStart TokenType = 10
	// TokenRangeBasicEnd marks the end of basic token types (exclusive)
	TokenRangeBasicEnd TokenType = 30

	// TokenRangeStringStart marks the beginning of string literal types
	TokenRangeStringStart TokenType = 30
	// TokenRangeStringEnd marks the end of string literal types (exclusive)
	TokenRangeStringEnd TokenType = 50

	// TokenRangeOperatorStart marks the beginning of operator types
	TokenRangeOperatorStart TokenType = 50
	// TokenRangeOperatorEnd marks the end of operator types (exclusive)
	TokenRangeOperatorEnd TokenType = 150

	// TokenRangeKeywordStart marks the beginning of SQL keyword types
	TokenRangeKeywordStart TokenType = 200
	// TokenRangeKeywordEnd marks the end of SQL keyword types (exclusive)
	TokenRangeKeywordEnd TokenType = 500

	// TokenRangeDataTypeStart marks the beginning of data type keywords
	TokenRangeDataTypeStart TokenType = 430
	// TokenRangeDataTypeEnd marks the end of data type keywords (exclusive)
	TokenRangeDataTypeEnd TokenType = 450
)

// Token type constants with explicit values to avoid collisions.
//
// Constants are assigned explicit numeric values to guarantee stability across
// versions. Adding new token types must not change existing values.
const (
	// TokenTypeEOF marks the end of the SQL input stream. Every token slice
	// produced by the tokenizer is terminated with an EOF token.
	TokenTypeEOF TokenType = 0
	// TokenTypeUnknown is assigned to tokens that cannot be classified. This
	// typically signals a tokenizer bug or an unsupported input character.
	TokenTypeUnknown TokenType = 1

	// Basic token types (10-29)

	// TokenTypeWord represents an unquoted keyword or identifier word token.
	// The Token.Word field holds keyword metadata when the word is a SQL keyword.
	TokenTypeWord TokenType = 10
	// TokenTypeNumber represents a numeric literal (integer or floating-point).
	// Token.Long is true when the value requires int64 representation.
	TokenTypeNumber TokenType = 11
	// TokenTypeChar represents a single character token that does not fit other categories.
	TokenTypeChar TokenType = 12
	// TokenTypeWhitespace represents whitespace (spaces, newlines, tabs) or comments.
	TokenTypeWhitespace TokenType = 13
	// TokenTypeIdentifier represents a quoted identifier such as "column name" or `table`.
	TokenTypeIdentifier TokenType = 14
	// TokenTypePlaceholder represents a query parameter placeholder such as ? or $1.
	TokenTypePlaceholder TokenType = 15

	// String literals (30-49)

	// TokenTypeString is the generic string literal type used when the specific
	// quoting style is not important (e.g., for dialect-agnostic processing).
	TokenTypeString TokenType = 30
	// TokenTypeSingleQuotedString represents a SQL string literal enclosed in single quotes: 'value'.
	TokenTypeSingleQuotedString TokenType = 31
	// TokenTypeDoubleQuotedString represents a string enclosed in double quotes: "value".
	// In standard SQL this is a quoted identifier; in MySQL it can be a string literal.
	TokenTypeDoubleQuotedString TokenType = 32
	// TokenTypeTripleSingleQuotedString represents a string enclosed in triple single quotes: '''value'''.
	TokenTypeTripleSingleQuotedString TokenType = 33
	// TokenTypeTripleDoubleQuotedString represents a string enclosed in triple double quotes: """value""".
	TokenTypeTripleDoubleQuotedString TokenType = 34
	// TokenTypeDollarQuotedString represents a PostgreSQL dollar-quoted string: $$value$$ or $tag$value$tag$.
	TokenTypeDollarQuotedString TokenType = 35
	// TokenTypeByteStringLiteral represents a byte string literal such as b'bytes' (BigQuery).
	TokenTypeByteStringLiteral TokenType = 36
	// TokenTypeNationalStringLiteral represents an ANSI national character set string: N'value'.
	TokenTypeNationalStringLiteral TokenType = 37
	// TokenTypeEscapedStringLiteral represents a PostgreSQL escaped string: E'value\n'.
	TokenTypeEscapedStringLiteral TokenType = 38
	// TokenTypeUnicodeStringLiteral represents an ANSI Unicode string: U&'value'.
	TokenTypeUnicodeStringLiteral TokenType = 39
	// TokenTypeHexStringLiteral represents a hexadecimal string literal: X'DEADBEEF'.
	TokenTypeHexStringLiteral TokenType = 40

	// Operators and punctuation (50-99)

	// TokenTypeOperator is the generic operator type for operators not covered by a more specific constant.
	TokenTypeOperator TokenType = 50
	// TokenTypeComma represents the , separator used in lists and clauses.
	TokenTypeComma TokenType = 51
	// TokenTypeEq represents the = equality or assignment operator.
	TokenTypeEq TokenType = 52
	// TokenTypeDoubleEq represents the == equality operator (MySQL, SQLite).
	TokenTypeDoubleEq TokenType = 53
	// TokenTypeNeq represents the <> or != inequality operator.
	TokenTypeNeq TokenType = 54
	// TokenTypeLt represents the < less-than comparison operator.
	TokenTypeLt TokenType = 55
	// TokenTypeGt represents the > greater-than comparison operator.
	TokenTypeGt TokenType = 56
	// TokenTypeLtEq represents the <= less-than-or-equal comparison operator.
	TokenTypeLtEq TokenType = 57
	// TokenTypeGtEq represents the >= greater-than-or-equal comparison operator.
	TokenTypeGtEq TokenType = 58
	// TokenTypeSpaceship represents the <=> NULL-safe equality operator (MySQL).
	TokenTypeSpaceship TokenType = 59
	// TokenTypePlus represents the + addition operator.
	TokenTypePlus TokenType = 60
	// TokenTypeMinus represents the - subtraction or negation operator.
	TokenTypeMinus TokenType = 61
	// TokenTypeMul represents the * multiplication operator or SELECT * wildcard.
	TokenTypeMul TokenType = 62
	// TokenTypeDiv represents the / division operator.
	TokenTypeDiv TokenType = 63
	// TokenTypeDuckIntDiv represents the // integer division operator (DuckDB).
	TokenTypeDuckIntDiv TokenType = 64
	// TokenTypeMod represents the % modulo operator.
	TokenTypeMod TokenType = 65
	// TokenTypeStringConcat represents the || string concatenation operator (SQL standard).
	TokenTypeStringConcat TokenType = 66
	// TokenTypeLParen represents the ( left parenthesis.
	TokenTypeLParen    TokenType = 67
	TokenTypeLeftParen TokenType = 67 // TokenTypeLeftParen is an alias for TokenTypeLParen for backward compatibility.
	// TokenTypeRParen represents the ) right parenthesis.
	TokenTypeRParen     TokenType = 68
	TokenTypeRightParen TokenType = 68 // TokenTypeRightParen is an alias for TokenTypeRParen for backward compatibility.
	// TokenTypePeriod represents the . dot/period used for qualified names (schema.table.column).
	TokenTypePeriod TokenType = 69
	TokenTypeDot    TokenType = 69 // TokenTypeDot is an alias for TokenTypePeriod for backward compatibility.
	// TokenTypeColon represents the : colon used in named parameters (:param) and slices.
	TokenTypeColon TokenType = 70
	// TokenTypeDoubleColon represents the :: PostgreSQL type cast operator (expr::type).
	TokenTypeDoubleColon TokenType = 71
	// TokenTypeAssignment represents the := assignment operator used in PL/SQL and named arguments.
	TokenTypeAssignment TokenType = 72
	// TokenTypeSemicolon represents the ; statement terminator.
	TokenTypeSemicolon TokenType = 73
	// TokenTypeBackslash represents the \ backslash character.
	TokenTypeBackslash TokenType = 74
	// TokenTypeLBracket represents the [ left square bracket used for array subscripts and array literals.
	TokenTypeLBracket TokenType = 75
	// TokenTypeRBracket represents the ] right square bracket.
	TokenTypeRBracket TokenType = 76
	// TokenTypeAmpersand represents the & bitwise AND operator.
	TokenTypeAmpersand TokenType = 77
	// TokenTypePipe represents the | bitwise OR operator.
	TokenTypePipe TokenType = 78
	// TokenTypeCaret represents the ^ bitwise XOR or exponentiation operator.
	TokenTypeCaret TokenType = 79
	// TokenTypeLBrace represents the { left curly brace used in JSON literals and format strings.
	TokenTypeLBrace TokenType = 80
	// TokenTypeRBrace represents the } right curly brace.
	TokenTypeRBrace TokenType = 81
	// TokenTypeRArrow represents the => fat arrow used in named argument syntax.
	TokenTypeRArrow TokenType = 82
	// TokenTypeSharp represents the # hash character used in PostgreSQL path operators.
	TokenTypeSharp TokenType = 83
	// TokenTypeTilde represents the ~ regular expression match operator (PostgreSQL).
	TokenTypeTilde TokenType = 84
	// TokenTypeExclamationMark represents the ! logical NOT or factorial operator.
	TokenTypeExclamationMark TokenType = 85
	// TokenTypeAtSign represents the @ at-sign used in PostgreSQL full-text search and JSON operators.
	TokenTypeAtSign TokenType = 86
	// TokenTypeQuestion represents the ? parameter placeholder (JDBC) and JSON key existence operator (PostgreSQL).
	TokenTypeQuestion TokenType = 87

	// Compound operators (100-149)
	// These multi-character operators are produced when the tokenizer recognises
	// a specific combination of characters as a single logical token.

	// TokenTypeTildeAsterisk represents the ~* case-insensitive regex match operator (PostgreSQL).
	TokenTypeTildeAsterisk TokenType = 100
	// TokenTypeExclamationMarkTilde represents the !~ regex non-match operator (PostgreSQL).
	TokenTypeExclamationMarkTilde TokenType = 101
	// TokenTypeExclamationMarkTildeAsterisk represents the !~* case-insensitive regex non-match operator (PostgreSQL).
	TokenTypeExclamationMarkTildeAsterisk TokenType = 102
	// TokenTypeDoubleTilde represents the ~~ LIKE operator alias (PostgreSQL).
	TokenTypeDoubleTilde TokenType = 103
	// TokenTypeDoubleTildeAsterisk represents the ~~* ILIKE operator alias (PostgreSQL).
	TokenTypeDoubleTildeAsterisk TokenType = 104
	// TokenTypeExclamationMarkDoubleTilde represents the !~~ NOT LIKE operator alias (PostgreSQL).
	TokenTypeExclamationMarkDoubleTilde TokenType = 105
	// TokenTypeExclamationMarkDoubleTildeAsterisk represents the !~~* NOT ILIKE operator alias (PostgreSQL).
	TokenTypeExclamationMarkDoubleTildeAsterisk TokenType = 106
	// TokenTypeShiftLeft represents the << bitwise left-shift operator.
	TokenTypeShiftLeft TokenType = 107
	// TokenTypeShiftRight represents the >> bitwise right-shift operator.
	TokenTypeShiftRight TokenType = 108
	// TokenTypeOverlap represents the && range overlap operator (PostgreSQL).
	TokenTypeOverlap TokenType = 109
	// TokenTypeDoubleExclamationMark represents the !! prefix factorial operator (PostgreSQL).
	TokenTypeDoubleExclamationMark TokenType = 110
	// TokenTypeCaretAt represents the ^@ starts-with string operator (PostgreSQL 11+).
	TokenTypeCaretAt TokenType = 111
	// TokenTypePGSquareRoot represents the |/ square root prefix operator (PostgreSQL).
	TokenTypePGSquareRoot TokenType = 112
	// TokenTypePGCubeRoot represents the ||/ cube root prefix operator (PostgreSQL).
	TokenTypePGCubeRoot TokenType = 113

	// JSON/JSONB operators (PostgreSQL)

	// TokenTypeArrow represents the -> operator that returns a JSON field value as a JSON object.
	// Example: data->'name' returns the "name" field as JSON.
	TokenTypeArrow TokenType = 114
	// TokenTypeLongArrow represents the ->> operator that returns a JSON field value as text.
	// Example: data->>'name' returns the "name" field as a text string.
	TokenTypeLongArrow TokenType = 115
	// TokenTypeHashArrow represents the #> operator that returns a JSON value at a path as JSON.
	// Example: data#>'{address,city}' returns the nested value as JSON.
	TokenTypeHashArrow TokenType = 116
	// TokenTypeHashLongArrow represents the #>> operator that returns a JSON value at a path as text.
	// Example: data#>>'{address,city}' returns the nested value as text.
	TokenTypeHashLongArrow TokenType = 117
	// TokenTypeAtArrow represents the @> containment operator: left JSON value contains right.
	// Example: data @> '{"status":"active"}' checks if data contains the given JSON.
	TokenTypeAtArrow TokenType = 118
	// TokenTypeArrowAt represents the <@ containment operator: left JSON value is contained by right.
	// Example: '{"a":1}' <@ data checks if the left-hand JSON is a subset of data.
	TokenTypeArrowAt TokenType = 119
	// TokenTypeHashMinus represents the #- operator that deletes a key or index at the given path.
	// Example: data #- '{address,zip}' removes the "zip" key from the nested "address" object.
	TokenTypeHashMinus TokenType = 120
	// TokenTypeAtQuestion represents the @? operator that tests whether a JSON path returns any values.
	// Example: data @? '$.address.city' checks whether the path produces a result.
	TokenTypeAtQuestion TokenType = 121
	// TokenTypeAtAt represents the @@ operator used for full-text search matching.
	// Example: to_tsvector(text) @@ to_tsquery('query').
	TokenTypeAtAt TokenType = 122
	// TokenTypeQuestionAnd represents the ?& operator that checks whether all given keys exist.
	// Example: data ?& array['name','email'] returns true if both keys exist in the JSON object.
	TokenTypeQuestionAnd TokenType = 123
	// TokenTypeQuestionPipe represents the ?| operator that checks whether any of the given keys exist.
	// Example: data ?| array['name','email'] returns true if at least one key exists.
	TokenTypeQuestionPipe TokenType = 124
	// TokenTypeCustomBinaryOperator represents a user-defined or dialect-specific binary operator
	// not covered by any other constant (e.g., custom PostgreSQL operators).
	TokenTypeCustomBinaryOperator TokenType = 125

	// SQL Keywords (200-399)
	// These token types represent reserved and non-reserved SQL keywords.

	// TokenTypeKeyword is the generic keyword token type for words that are recognised
	// as SQL keywords but do not have a more specific constant assigned.
	TokenTypeKeyword TokenType = 200
	// TokenTypeSelect represents the SELECT keyword that begins a query.
	TokenTypeSelect TokenType = 201
	// TokenTypeFrom represents the FROM keyword that introduces the table source.
	TokenTypeFrom TokenType = 202
	// TokenTypeWhere represents the WHERE keyword that begins the filter condition.
	TokenTypeWhere TokenType = 203
	// TokenTypeJoin represents the JOIN keyword (typically preceded by INNER, LEFT, etc.).
	TokenTypeJoin TokenType = 204
	// TokenTypeInner represents the INNER keyword used in INNER JOIN.
	TokenTypeInner TokenType = 205
	// TokenTypeLeft represents the LEFT keyword used in LEFT JOIN and LEFT OUTER JOIN.
	TokenTypeLeft TokenType = 206
	// TokenTypeRight represents the RIGHT keyword used in RIGHT JOIN and RIGHT OUTER JOIN.
	TokenTypeRight TokenType = 207
	// TokenTypeOuter represents the OUTER keyword used in LEFT/RIGHT/FULL OUTER JOIN.
	TokenTypeOuter TokenType = 208
	// TokenTypeOn represents the ON keyword that introduces a join condition.
	TokenTypeOn TokenType = 209
	// TokenTypeAs represents the AS keyword used in aliases (table AS alias, column AS alias).
	TokenTypeAs TokenType = 210
	// TokenTypeAnd represents the AND logical operator combining conditions.
	TokenTypeAnd TokenType = 211
	// TokenTypeOr represents the OR logical operator combining conditions.
	TokenTypeOr TokenType = 212
	// TokenTypeNot represents the NOT logical negation operator.
	TokenTypeNot TokenType = 213
	// TokenTypeIn represents the IN operator for membership tests (expr IN (list)).
	TokenTypeIn TokenType = 214
	// TokenTypeLike represents the LIKE pattern-matching operator.
	TokenTypeLike TokenType = 215
	// TokenTypeBetween represents the BETWEEN range operator (expr BETWEEN low AND high).
	TokenTypeBetween TokenType = 216
	// TokenTypeIs represents the IS operator used with NULL, TRUE, FALSE.
	TokenTypeIs TokenType = 217
	// TokenTypeNull represents the NULL literal value.
	TokenTypeNull TokenType = 218
	// TokenTypeTrue represents the TRUE boolean literal.
	TokenTypeTrue TokenType = 219
	// TokenTypeFalse represents the FALSE boolean literal.
	TokenTypeFalse TokenType = 220
	// TokenTypeCase represents the CASE keyword beginning a conditional expression.
	TokenTypeCase TokenType = 221
	// TokenTypeWhen represents the WHEN keyword inside a CASE expression.
	TokenTypeWhen TokenType = 222
	// TokenTypeThen represents the THEN keyword inside a CASE WHEN clause.
	TokenTypeThen TokenType = 223
	// TokenTypeElse represents the ELSE keyword for the default branch in a CASE expression.
	TokenTypeElse TokenType = 224
	// TokenTypeEnd represents the END keyword closing a CASE expression or block.
	TokenTypeEnd TokenType = 225
	// TokenTypeGroup represents the GROUP keyword as part of GROUP BY.
	TokenTypeGroup TokenType = 226
	// TokenTypeBy represents the BY keyword used with GROUP BY and ORDER BY.
	TokenTypeBy TokenType = 227
	// TokenTypeHaving represents the HAVING keyword for filtering grouped results.
	TokenTypeHaving TokenType = 228
	// TokenTypeOrder represents the ORDER keyword as part of ORDER BY.
	TokenTypeOrder TokenType = 229
	// TokenTypeAsc represents the ASC sort direction keyword (ascending order).
	TokenTypeAsc TokenType = 230
	// TokenTypeDesc represents the DESC sort direction keyword (descending order).
	TokenTypeDesc TokenType = 231
	// TokenTypeLimit represents the LIMIT keyword for restricting result count (MySQL, PostgreSQL, SQLite).
	TokenTypeLimit TokenType = 232
	// TokenTypeOffset represents the OFFSET keyword for skipping rows in a result set.
	TokenTypeOffset TokenType = 233

	// DML Keywords (234-239)
	// Data Manipulation Language keywords for modifying table data.

	// TokenTypeInsert represents the INSERT keyword beginning an INSERT statement.
	TokenTypeInsert TokenType = 234
	// TokenTypeUpdate represents the UPDATE keyword beginning an UPDATE statement.
	TokenTypeUpdate TokenType = 235
	// TokenTypeDelete represents the DELETE keyword beginning a DELETE statement.
	TokenTypeDelete TokenType = 236
	// TokenTypeInto represents the INTO keyword used in INSERT INTO and other clauses.
	TokenTypeInto TokenType = 237
	// TokenTypeValues represents the VALUES keyword introducing a list of row values.
	TokenTypeValues TokenType = 238
	// TokenTypeSet represents the SET keyword introducing column assignments in UPDATE.
	TokenTypeSet TokenType = 239

	// DDL Keywords (240-249)
	// Data Definition Language keywords for managing database schema objects.

	// TokenTypeCreate represents the CREATE keyword beginning a DDL creation statement.
	TokenTypeCreate TokenType = 240
	// TokenTypeAlter represents the ALTER keyword beginning a DDL modification statement.
	TokenTypeAlter TokenType = 241
	// TokenTypeDrop represents the DROP keyword beginning a DDL deletion statement.
	TokenTypeDrop TokenType = 242
	// TokenTypeTable represents the TABLE keyword used in DDL statements (CREATE TABLE, etc.).
	TokenTypeTable TokenType = 243
	// TokenTypeIndex represents the INDEX keyword used in CREATE/DROP INDEX statements.
	TokenTypeIndex TokenType = 244
	// TokenTypeView represents the VIEW keyword used in CREATE/DROP VIEW statements.
	TokenTypeView TokenType = 245
	// TokenTypeColumn represents the COLUMN keyword used in ALTER TABLE ADD/DROP COLUMN.
	TokenTypeColumn TokenType = 246
	// TokenTypeDatabase represents the DATABASE keyword used in CREATE/DROP DATABASE.
	TokenTypeDatabase TokenType = 247
	// TokenTypeSchema represents the SCHEMA keyword used in CREATE/DROP SCHEMA.
	TokenTypeSchema TokenType = 248
	// TokenTypeTrigger represents the TRIGGER keyword used in CREATE/DROP TRIGGER.
	TokenTypeTrigger TokenType = 249

	// Aggregate functions (250-269)
	// Standard SQL aggregate function keywords recognised by the tokenizer.

	// TokenTypeCount represents the COUNT aggregate function.
	TokenTypeCount TokenType = 250
	// TokenTypeSum represents the SUM aggregate function.
	TokenTypeSum TokenType = 251
	// TokenTypeAvg represents the AVG (average) aggregate function.
	TokenTypeAvg TokenType = 252
	// TokenTypeMin represents the MIN aggregate function returning the smallest value.
	TokenTypeMin TokenType = 253
	// TokenTypeMax represents the MAX aggregate function returning the largest value.
	TokenTypeMax TokenType = 254

	// Compound keywords (270-279)
	// Multi-word compound SQL keywords represented as single token types for convenience.

	// TokenTypeGroupBy represents the compound GROUP BY keyword pair.
	TokenTypeGroupBy TokenType = 270
	// TokenTypeOrderBy represents the compound ORDER BY keyword pair.
	TokenTypeOrderBy TokenType = 271
	// TokenTypeLeftJoin represents the compound LEFT JOIN keyword pair.
	TokenTypeLeftJoin TokenType = 272
	// TokenTypeRightJoin represents the compound RIGHT JOIN keyword pair.
	TokenTypeRightJoin TokenType = 273
	// TokenTypeInnerJoin represents the compound INNER JOIN keyword pair.
	TokenTypeInnerJoin TokenType = 274
	// TokenTypeOuterJoin represents the compound OUTER JOIN keyword pair.
	TokenTypeOuterJoin TokenType = 275
	// TokenTypeFullJoin represents the compound FULL JOIN keyword pair.
	TokenTypeFullJoin TokenType = 276
	// TokenTypeCrossJoin represents the compound CROSS JOIN keyword pair.
	TokenTypeCrossJoin TokenType = 277

	// CTE and Set Operations (280-299)

	// TokenTypeWith represents the WITH keyword beginning a Common Table Expression (CTE).
	TokenTypeWith TokenType = 280
	// TokenTypeRecursive represents the RECURSIVE modifier in WITH RECURSIVE CTEs.
	TokenTypeRecursive TokenType = 281
	// TokenTypeUnion represents the UNION set operation combining two result sets.
	TokenTypeUnion TokenType = 282
	// TokenTypeExcept represents the EXCEPT set operation returning rows in the left set not in the right.
	TokenTypeExcept TokenType = 283
	// TokenTypeIntersect represents the INTERSECT set operation returning rows present in both sets.
	TokenTypeIntersect TokenType = 284
	// TokenTypeAll represents the ALL modifier used with UNION/EXCEPT/INTERSECT and quantified predicates.
	TokenTypeAll TokenType = 285

	// Window Function Keywords (300-319)
	// Keywords used within window function OVER clauses and frame specifications.

	// TokenTypeOver represents the OVER keyword introducing a window specification.
	TokenTypeOver TokenType = 300
	// TokenTypePartition represents the PARTITION keyword in PARTITION BY window clause.
	TokenTypePartition TokenType = 301
	// TokenTypeRows represents the ROWS mode in a window frame (physical row offsets).
	TokenTypeRows TokenType = 302
	// TokenTypeRange represents the RANGE mode in a window frame (logical value offsets).
	TokenTypeRange TokenType = 303
	// TokenTypeUnbounded represents UNBOUNDED in window frames (UNBOUNDED PRECEDING/FOLLOWING).
	TokenTypeUnbounded TokenType = 304
	// TokenTypePreceding represents PRECEDING in window frame bounds.
	TokenTypePreceding TokenType = 305
	// TokenTypeFollowing represents FOLLOWING in window frame bounds.
	TokenTypeFollowing TokenType = 306
	// TokenTypeCurrent represents CURRENT in CURRENT ROW frame bound.
	TokenTypeCurrent TokenType = 307
	// TokenTypeRow represents ROW in the CURRENT ROW window frame bound.
	TokenTypeRow TokenType = 308
	// TokenTypeGroups represents the GROUPS mode in a window frame (peer group offsets, SQL:2011).
	TokenTypeGroups TokenType = 309
	// TokenTypeFilter represents the FILTER keyword for conditional aggregation (e.g., COUNT(*) FILTER (WHERE ...)).
	TokenTypeFilter TokenType = 310
	// TokenTypeExclude represents the EXCLUDE keyword in window frame EXCLUDE clauses.
	TokenTypeExclude TokenType = 311

	// Additional Join Keywords (320-329)

	// TokenTypeCross represents the CROSS keyword used in CROSS JOIN.
	TokenTypeCross TokenType = 320
	// TokenTypeNatural represents the NATURAL keyword used in NATURAL JOIN (joins on all matching column names).
	TokenTypeNatural TokenType = 321
	// TokenTypeFull represents the FULL keyword used in FULL OUTER JOIN.
	TokenTypeFull TokenType = 322
	// TokenTypeUsing represents the USING keyword that specifies shared column names in a JOIN.
	TokenTypeUsing TokenType = 323
	// TokenTypeLateral represents the LATERAL keyword allowing correlated subqueries in the FROM clause.
	// Example: FROM users u, LATERAL (SELECT * FROM orders WHERE user_id = u.id) o
	TokenTypeLateral TokenType = 324

	// Constraint Keywords (330-349)
	// Keywords used in table and column constraint definitions.

	// TokenTypePrimary represents the PRIMARY keyword in PRIMARY KEY constraints.
	TokenTypePrimary TokenType = 330
	// TokenTypeKey represents the KEY keyword in PRIMARY KEY and FOREIGN KEY constraints.
	TokenTypeKey TokenType = 331
	// TokenTypeForeign represents the FOREIGN keyword in FOREIGN KEY constraints.
	TokenTypeForeign TokenType = 332
	// TokenTypeReferences represents the REFERENCES keyword in FOREIGN KEY constraints.
	TokenTypeReferences TokenType = 333
	// TokenTypeUnique represents the UNIQUE constraint keyword.
	TokenTypeUnique TokenType = 334
	// TokenTypeCheck represents the CHECK constraint keyword.
	TokenTypeCheck TokenType = 335
	// TokenTypeDefault represents the DEFAULT constraint keyword specifying a default column value.
	TokenTypeDefault TokenType = 336
	// TokenTypeAutoIncrement represents the AUTO_INCREMENT column attribute (MySQL).
	// In PostgreSQL, the equivalent is SERIAL or GENERATED ALWAYS AS IDENTITY.
	TokenTypeAutoIncrement TokenType = 337
	// TokenTypeConstraint represents the CONSTRAINT keyword that names a table constraint.
	TokenTypeConstraint TokenType = 338
	// TokenTypeNotNull represents the NOT NULL constraint keyword pair.
	TokenTypeNotNull TokenType = 339
	// TokenTypeNullable represents the NULLABLE keyword (some dialects allow explicit nullable columns).
	TokenTypeNullable TokenType = 340

	// Additional SQL Keywords (350-399)

	// TokenTypeDistinct represents the DISTINCT keyword for removing duplicate rows.
	TokenTypeDistinct TokenType = 350
	// TokenTypeExists represents the EXISTS keyword for subquery existence tests.
	TokenTypeExists TokenType = 351
	// TokenTypeAny represents the ANY quantifier used with comparison operators and subqueries.
	TokenTypeAny TokenType = 352
	// TokenTypeSome represents the SOME quantifier (synonym for ANY in most dialects).
	TokenTypeSome TokenType = 353
	// TokenTypeCast represents the CAST keyword for explicit type conversion (CAST(expr AS type)).
	TokenTypeCast TokenType = 354
	// TokenTypeConvert represents the CONVERT keyword for type or charset conversion (MySQL, SQL Server).
	TokenTypeConvert TokenType = 355
	// TokenTypeCollate represents the COLLATE keyword specifying a collation for comparisons.
	TokenTypeCollate TokenType = 356
	// TokenTypeCascade represents the CASCADE option in DROP and constraint definitions.
	TokenTypeCascade TokenType = 357
	// TokenTypeRestrict represents the RESTRICT option preventing drops when dependent objects exist.
	TokenTypeRestrict TokenType = 358
	// TokenTypeReplace represents the REPLACE keyword used in INSERT OR REPLACE and REPLACE INTO (MySQL).
	TokenTypeReplace TokenType = 359
	// TokenTypeRename represents the RENAME keyword used in ALTER TABLE RENAME.
	TokenTypeRename TokenType = 360
	// TokenTypeTo represents the TO keyword used in RENAME ... TO and GRANT ... TO.
	TokenTypeTo TokenType = 361
	// TokenTypeIf represents the IF keyword used in IF EXISTS and IF NOT EXISTS clauses.
	TokenTypeIf TokenType = 362
	// TokenTypeOnly represents the ONLY keyword used in inheritance-aware queries (PostgreSQL).
	TokenTypeOnly TokenType = 363
	// TokenTypeFor represents the FOR keyword used in FOR UPDATE, FOR SHARE, and FETCH FOR.
	TokenTypeFor TokenType = 364
	// TokenTypeNulls represents the NULLS keyword used in NULLS FIRST / NULLS LAST ordering.
	TokenTypeNulls TokenType = 365
	// TokenTypeFirst represents the FIRST keyword used in NULLS FIRST and FETCH FIRST.
	TokenTypeFirst TokenType = 366
	// TokenTypeLast represents the LAST keyword used in NULLS LAST.
	TokenTypeLast TokenType = 367
	// TokenTypeFetch represents the FETCH keyword beginning a FETCH FIRST/NEXT clause (SQL standard LIMIT).
	// Example: FETCH FIRST 10 ROWS ONLY
	TokenTypeFetch TokenType = 368
	// TokenTypeNext represents the NEXT keyword used in FETCH NEXT ... ROWS ONLY.
	TokenTypeNext TokenType = 369

	// MERGE Statement Keywords (370-379)
	// Keywords used in SQL:2003 MERGE statements.

	// TokenTypeMerge represents the MERGE keyword beginning a MERGE statement.
	TokenTypeMerge TokenType = 370
	// TokenTypeMatched represents the MATCHED keyword in WHEN MATCHED and WHEN NOT MATCHED clauses.
	TokenTypeMatched TokenType = 371
	// TokenTypeTarget represents the TARGET keyword (used in some dialect MERGE syntax).
	TokenTypeTarget TokenType = 372
	// TokenTypeSource represents the SOURCE keyword (used in some dialect MERGE syntax).
	TokenTypeSource TokenType = 373

	// Materialized View and FETCH clause Keywords (374-379)

	// TokenTypeMaterialized represents the MATERIALIZED keyword in CREATE/DROP/REFRESH MATERIALIZED VIEW.
	TokenTypeMaterialized TokenType = 374
	// TokenTypeRefresh represents the REFRESH keyword in REFRESH MATERIALIZED VIEW.
	TokenTypeRefresh TokenType = 375
	// TokenTypeTies represents the TIES keyword in FETCH FIRST n ROWS WITH TIES.
	// WITH TIES causes the last group of rows with equal ordering values to all be returned.
	TokenTypeTies TokenType = 376
	// TokenTypePercent represents the PERCENT keyword in FETCH FIRST n PERCENT ROWS ONLY.
	TokenTypePercent TokenType = 377
	// TokenTypeTruncate represents the TRUNCATE keyword beginning a TRUNCATE TABLE statement.
	TokenTypeTruncate TokenType = 378
	// TokenTypeReturning represents the RETURNING keyword in PostgreSQL INSERT/UPDATE/DELETE statements.
	// RETURNING causes the modified rows to be returned as a result set.
	TokenTypeReturning TokenType = 379

	// Row Locking Keywords (380-389)
	// Keywords used in SELECT ... FOR UPDATE/SHARE row-locking clauses.

	// TokenTypeShare represents the SHARE keyword in FOR SHARE row locking.
	TokenTypeShare TokenType = 380
	// TokenTypeNoWait represents the NOWAIT keyword causing an immediate error instead of waiting
	// for locked rows (FOR UPDATE NOWAIT, FOR SHARE NOWAIT).
	TokenTypeNoWait TokenType = 381
	// TokenTypeSkip represents the SKIP keyword in FOR UPDATE SKIP LOCKED,
	// causing locked rows to be silently skipped.
	TokenTypeSkip TokenType = 382
	// TokenTypeLocked represents the LOCKED keyword in SKIP LOCKED.
	TokenTypeLocked TokenType = 383
	// TokenTypeOf represents the OF keyword in FOR UPDATE OF table_name,
	// restricting locking to specific tables in a JOIN.
	TokenTypeOf TokenType = 384

	// Grouping Set Keywords (390-399)
	// Keywords used for advanced grouping in GROUP BY clauses.

	// TokenTypeGroupingSets represents the GROUPING SETS keyword pair for
	// specifying explicit grouping combinations in GROUP BY.
	TokenTypeGroupingSets TokenType = 390
	// TokenTypeRollup represents the ROLLUP keyword for hierarchical grouping subtotals.
	// Example: GROUP BY ROLLUP (year, quarter, month)
	TokenTypeRollup TokenType = 391
	// TokenTypeCube represents the CUBE keyword for all possible grouping combinations.
	// Example: GROUP BY CUBE (region, product)
	TokenTypeCube TokenType = 392
	// TokenTypeGrouping represents the GROUPING function keyword that indicates whether
	// a column is aggregated in a GROUPING SETS/ROLLUP/CUBE expression.
	TokenTypeGrouping TokenType = 393
	// TokenTypeSets represents the SETS keyword used in GROUPING SETS (...).
	TokenTypeSets TokenType = 394
	// TokenTypeArray represents the ARRAY keyword for PostgreSQL array constructors.
	// Example: ARRAY[1, 2, 3] or ARRAY(SELECT id FROM users)
	TokenTypeArray TokenType = 395
	// TokenTypeWithin represents the WITHIN keyword in ordered-set aggregate functions.
	// Example: PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY salary)
	TokenTypeWithin TokenType = 396

	// Role/Permission Keywords (400-419)
	// Keywords used in GRANT, REVOKE, CREATE/ALTER ROLE, and user management statements.

	// TokenTypeRole represents the ROLE keyword in CREATE/ALTER/DROP ROLE statements.
	TokenTypeRole TokenType = 400
	// TokenTypeUser represents the USER keyword in CREATE/ALTER/DROP USER statements.
	TokenTypeUser TokenType = 401
	// TokenTypeGrant represents the GRANT keyword for granting privileges to roles/users.
	TokenTypeGrant TokenType = 402
	// TokenTypeRevoke represents the REVOKE keyword for revoking previously granted privileges.
	TokenTypeRevoke TokenType = 403
	// TokenTypePrivilege represents the PRIVILEGE keyword in GRANT/REVOKE statements.
	TokenTypePrivilege TokenType = 404
	// TokenTypePassword represents the PASSWORD keyword in ALTER USER ... PASSWORD statements.
	TokenTypePassword TokenType = 405
	// TokenTypeLogin represents the LOGIN option keyword in CREATE/ALTER ROLE ... LOGIN.
	TokenTypeLogin TokenType = 406
	// TokenTypeSuperuser represents the SUPERUSER option keyword in CREATE/ALTER ROLE.
	TokenTypeSuperuser TokenType = 407
	// TokenTypeCreateDB represents the CREATEDB option keyword allowing a role to create databases.
	TokenTypeCreateDB TokenType = 408
	// TokenTypeCreateRole represents the CREATEROLE option keyword allowing a role to create other roles.
	TokenTypeCreateRole TokenType = 409

	// Transaction Keywords (420-429)
	// Keywords for transaction control statements.

	// TokenTypeBegin represents the BEGIN keyword starting an explicit transaction block.
	TokenTypeBegin TokenType = 420
	// TokenTypeCommit represents the COMMIT keyword permanently saving a transaction.
	TokenTypeCommit TokenType = 421
	// TokenTypeRollback represents the ROLLBACK keyword undoing a transaction.
	TokenTypeRollback TokenType = 422
	// TokenTypeSavepoint represents the SAVEPOINT keyword creating a named transaction savepoint.
	TokenTypeSavepoint TokenType = 423

	// Data Type Keywords (430-449)
	// SQL built-in data type keywords recognised by the tokenizer.

	// TokenTypeInt represents the INT data type keyword (32-bit signed integer).
	TokenTypeInt TokenType = 430
	// TokenTypeInteger represents the INTEGER data type keyword (synonym for INT in most dialects).
	TokenTypeInteger TokenType = 431
	// TokenTypeBigInt represents the BIGINT data type keyword (64-bit signed integer).
	TokenTypeBigInt TokenType = 432
	// TokenTypeSmallInt represents the SMALLINT data type keyword (16-bit signed integer).
	TokenTypeSmallInt TokenType = 433
	// TokenTypeFloat represents the FLOAT data type keyword (single or double precision floating-point).
	TokenTypeFloat TokenType = 434
	// TokenTypeDouble represents the DOUBLE or DOUBLE PRECISION data type keyword.
	TokenTypeDouble TokenType = 435
	// TokenTypeDecimal represents the DECIMAL(p,s) fixed-precision data type keyword.
	TokenTypeDecimal TokenType = 436
	// TokenTypeNumeric represents the NUMERIC(p,s) fixed-precision data type keyword (synonym for DECIMAL).
	TokenTypeNumeric TokenType = 437
	// TokenTypeVarchar represents the VARCHAR(n) variable-length character data type keyword.
	TokenTypeVarchar TokenType = 438
	// TokenTypeCharDataType represents the CHAR(n) fixed-length character data type keyword.
	// Note: this is distinct from TokenTypeChar (value 12) which represents a single character token.
	TokenTypeCharDataType TokenType = 439
	// TokenTypeText represents the TEXT data type keyword for variable-length text.
	TokenTypeText TokenType = 440
	// TokenTypeBoolean represents the BOOLEAN data type keyword.
	TokenTypeBoolean TokenType = 441
	// TokenTypeDate represents the DATE data type keyword (calendar date without time).
	TokenTypeDate TokenType = 442
	// TokenTypeTime represents the TIME data type keyword (time of day without date).
	TokenTypeTime TokenType = 443
	// TokenTypeTimestamp represents the TIMESTAMP data type keyword (date and time).
	TokenTypeTimestamp TokenType = 444
	// TokenTypeInterval represents the INTERVAL data type keyword for time durations.
	TokenTypeInterval TokenType = 445
	// TokenTypeBlob represents the BLOB data type keyword for binary large objects.
	TokenTypeBlob TokenType = 446
	// TokenTypeClob represents the CLOB data type keyword for character large objects.
	TokenTypeClob TokenType = 447
	// TokenTypeJson represents the JSON data type keyword (PostgreSQL, MySQL 5.7+).
	TokenTypeJson TokenType = 448
	// TokenTypeUuid represents the UUID data type keyword (PostgreSQL, SQL Server).
	TokenTypeUuid TokenType = 449

	// Special Token Types (500+)
	// Miscellaneous tokens that do not fit cleanly into a single numeric range.

	// TokenTypeIllegal is used for parser compatibility with internal ILLEGAL token values.
	TokenTypeIllegal TokenType = 500
	// TokenTypeAsterisk represents an explicit * token used as a wildcard or multiply operator.
	// Distinct from TokenTypeMul (62) to allow unambiguous identification of the asterisk character.
	TokenTypeAsterisk TokenType = 501
	// TokenTypeDoublePipe represents the || string concatenation operator (SQL standard).
	// Distinct from TokenTypeStringConcat (66) for cases where dialect disambiguation is needed.
	TokenTypeDoublePipe TokenType = 502
	// TokenTypeILike represents the ILIKE case-insensitive pattern-matching operator (PostgreSQL).
	TokenTypeILike TokenType = 503
	// TokenTypeAdd represents the ADD keyword used in ALTER TABLE ADD COLUMN.
	TokenTypeAdd TokenType = 504
	// TokenTypeNosuperuser represents the NOSUPERUSER option in ALTER ROLE, removing superuser privilege.
	TokenTypeNosuperuser TokenType = 505
	// TokenTypeNocreatedb represents the NOCREATEDB option in ALTER ROLE, removing database creation privilege.
	TokenTypeNocreatedb TokenType = 506
	// TokenTypeNocreaterole represents the NOCREATEROLE option in ALTER ROLE, removing role creation privilege.
	TokenTypeNocreaterole TokenType = 507
	// TokenTypeNologin represents the NOLOGIN option in ALTER ROLE, preventing login.
	TokenTypeNologin TokenType = 508
	// TokenTypeValid represents the VALID keyword used in VALID UNTIL role attribute.
	TokenTypeValid TokenType = 509
	// TokenTypeDcproperties represents the DCPROPERTIES keyword used in ALTER CONNECTOR.
	TokenTypeDcproperties TokenType = 510
	// TokenTypeUrl represents the URL keyword used in CREATE/ALTER CONNECTOR statements.
	TokenTypeUrl TokenType = 511
	// TokenTypeOwner represents the OWNER keyword used in ALTER CONNECTOR ... OWNER TO.
	TokenTypeOwner TokenType = 512
	// TokenTypeMember represents the MEMBER keyword used in ALTER ROLE ... MEMBER.
	TokenTypeMember TokenType = 513
	// TokenTypeConnector represents the CONNECTOR keyword used in CREATE/ALTER CONNECTOR statements.
	TokenTypeConnector TokenType = 514
	// TokenTypePolicy represents the POLICY keyword used in CREATE/ALTER POLICY statements.
	TokenTypePolicy TokenType = 515
	// TokenTypeUntil represents the UNTIL keyword used in VALID UNTIL date expressions.
	TokenTypeUntil TokenType = 516
	// TokenTypeReset represents the RESET keyword used in ALTER ROLE ... RESET parameter.
	TokenTypeReset TokenType = 517
	// TokenTypeShow represents the SHOW keyword used in MySQL SHOW TABLES, SHOW COLUMNS, etc.
	TokenTypeShow TokenType = 518
	// TokenTypeDescribe represents the DESCRIBE keyword used in MySQL DESCRIBE table_name.
	TokenTypeDescribe TokenType = 519
	// TokenTypeExplain represents the EXPLAIN keyword used to display query execution plans.
	TokenTypeExplain TokenType = 520
)

// String returns a string representation of the token type.
//
// Provides names for debugging, error messages, and logging.
// Uses a switch statement for O(1) compiled jump-table lookup.
// Covers ALL defined TokenType constants for completeness.
//
// Example:
//
//	tokenType := models.TokenTypeSelect
//	fmt.Println(tokenType.String()) // Output: "SELECT"
//
//	tokenType = models.TokenTypeLongArrow
//	fmt.Println(tokenType.String()) // Output: "LONG_ARROW"
func (t TokenType) String() string {
	switch t {
	// Special tokens
	case TokenTypeEOF:
		return "EOF"
	case TokenTypeUnknown:
		return "UNKNOWN"

	// Basic token types (10-29)
	case TokenTypeWord:
		return "WORD"
	case TokenTypeNumber:
		return "NUMBER"
	case TokenTypeChar:
		return "CHAR"
	case TokenTypeWhitespace:
		return "WHITESPACE"
	case TokenTypeIdentifier:
		return "IDENTIFIER"
	case TokenTypePlaceholder:
		return "PLACEHOLDER"

	// String literals (30-49)
	case TokenTypeString:
		return "STRING"
	case TokenTypeSingleQuotedString:
		return "STRING"
	case TokenTypeDoubleQuotedString:
		return "DOUBLE_QUOTED_STRING"
	case TokenTypeTripleSingleQuotedString:
		return "TRIPLE_SINGLE_QUOTED_STRING"
	case TokenTypeTripleDoubleQuotedString:
		return "TRIPLE_DOUBLE_QUOTED_STRING"
	case TokenTypeDollarQuotedString:
		return "DOLLAR_QUOTED_STRING"
	case TokenTypeByteStringLiteral:
		return "BYTE_STRING_LITERAL"
	case TokenTypeNationalStringLiteral:
		return "NATIONAL_STRING_LITERAL"
	case TokenTypeEscapedStringLiteral:
		return "ESCAPED_STRING_LITERAL"
	case TokenTypeUnicodeStringLiteral:
		return "UNICODE_STRING_LITERAL"
	case TokenTypeHexStringLiteral:
		return "HEX_STRING_LITERAL"

	// Operators and punctuation (50-99)
	case TokenTypeOperator:
		return "OPERATOR"
	case TokenTypeComma:
		return "COMMA"
	case TokenTypeEq:
		return "EQ"
	case TokenTypeDoubleEq:
		return "DOUBLE_EQ"
	case TokenTypeNeq:
		return "NEQ"
	case TokenTypeLt:
		return "LT"
	case TokenTypeGt:
		return "GT"
	case TokenTypeLtEq:
		return "LT_EQ"
	case TokenTypeGtEq:
		return "GT_EQ"
	case TokenTypeSpaceship:
		return "SPACESHIP"
	case TokenTypePlus:
		return "PLUS"
	case TokenTypeMinus:
		return "MINUS"
	case TokenTypeMul:
		return "MUL"
	case TokenTypeDiv:
		return "DIV"
	case TokenTypeDuckIntDiv:
		return "DUCK_INT_DIV"
	case TokenTypeMod:
		return "MOD"
	case TokenTypeStringConcat:
		return "STRING_CONCAT"
	case TokenTypeLParen:
		return "LPAREN"
	case TokenTypeRParen:
		return "RPAREN"
	case TokenTypePeriod:
		return "PERIOD"
	case TokenTypeColon:
		return "COLON"
	case TokenTypeDoubleColon:
		return "DOUBLE_COLON"
	case TokenTypeAssignment:
		return "ASSIGNMENT"
	case TokenTypeSemicolon:
		return "SEMICOLON"
	case TokenTypeBackslash:
		return "BACKSLASH"
	case TokenTypeLBracket:
		return "LBRACKET"
	case TokenTypeRBracket:
		return "RBRACKET"
	case TokenTypeAmpersand:
		return "AMPERSAND"
	case TokenTypePipe:
		return "PIPE"
	case TokenTypeCaret:
		return "CARET"
	case TokenTypeLBrace:
		return "LBRACE"
	case TokenTypeRBrace:
		return "RBRACE"
	case TokenTypeRArrow:
		return "R_ARROW"
	case TokenTypeSharp:
		return "SHARP"
	case TokenTypeTilde:
		return "TILDE"
	case TokenTypeExclamationMark:
		return "EXCLAMATION_MARK"
	case TokenTypeAtSign:
		return "AT_SIGN"
	case TokenTypeQuestion:
		return "QUESTION"

	// Compound operators (100-149)
	case TokenTypeTildeAsterisk:
		return "TILDE_ASTERISK"
	case TokenTypeExclamationMarkTilde:
		return "EXCLAMATION_MARK_TILDE"
	case TokenTypeExclamationMarkTildeAsterisk:
		return "EXCLAMATION_MARK_TILDE_ASTERISK"
	case TokenTypeDoubleTilde:
		return "DOUBLE_TILDE"
	case TokenTypeDoubleTildeAsterisk:
		return "DOUBLE_TILDE_ASTERISK"
	case TokenTypeExclamationMarkDoubleTilde:
		return "EXCLAMATION_MARK_DOUBLE_TILDE"
	case TokenTypeExclamationMarkDoubleTildeAsterisk:
		return "EXCLAMATION_MARK_DOUBLE_TILDE_ASTERISK"
	case TokenTypeShiftLeft:
		return "SHIFT_LEFT"
	case TokenTypeShiftRight:
		return "SHIFT_RIGHT"
	case TokenTypeOverlap:
		return "OVERLAP"
	case TokenTypeDoubleExclamationMark:
		return "DOUBLE_EXCLAMATION_MARK"
	case TokenTypeCaretAt:
		return "CARET_AT"
	case TokenTypePGSquareRoot:
		return "PG_SQUARE_ROOT"
	case TokenTypePGCubeRoot:
		return "PG_CUBE_ROOT"
	case TokenTypeArrow:
		return "ARROW"
	case TokenTypeLongArrow:
		return "LONG_ARROW"
	case TokenTypeHashArrow:
		return "HASH_ARROW"
	case TokenTypeHashLongArrow:
		return "HASH_LONG_ARROW"
	case TokenTypeAtArrow:
		return "AT_ARROW"
	case TokenTypeArrowAt:
		return "ARROW_AT"
	case TokenTypeHashMinus:
		return "HASH_MINUS"
	case TokenTypeAtQuestion:
		return "AT_QUESTION"
	case TokenTypeAtAt:
		return "AT_AT"
	case TokenTypeQuestionAnd:
		return "QUESTION_AND"
	case TokenTypeQuestionPipe:
		return "QUESTION_PIPE"
	case TokenTypeCustomBinaryOperator:
		return "CUSTOM_BINARY_OPERATOR"

	// SQL Keywords (200-399)
	case TokenTypeKeyword:
		return "KEYWORD"
	case TokenTypeSelect:
		return "SELECT"
	case TokenTypeFrom:
		return "FROM"
	case TokenTypeWhere:
		return "WHERE"
	case TokenTypeJoin:
		return "JOIN"
	case TokenTypeInner:
		return "INNER"
	case TokenTypeLeft:
		return "LEFT"
	case TokenTypeRight:
		return "RIGHT"
	case TokenTypeOuter:
		return "OUTER"
	case TokenTypeOn:
		return "ON"
	case TokenTypeAs:
		return "AS"
	case TokenTypeAnd:
		return "AND"
	case TokenTypeOr:
		return "OR"
	case TokenTypeNot:
		return "NOT"
	case TokenTypeIn:
		return "IN"
	case TokenTypeLike:
		return "LIKE"
	case TokenTypeBetween:
		return "BETWEEN"
	case TokenTypeIs:
		return "IS"
	case TokenTypeNull:
		return "NULL"
	case TokenTypeTrue:
		return "TRUE"
	case TokenTypeFalse:
		return "FALSE"
	case TokenTypeCase:
		return "CASE"
	case TokenTypeWhen:
		return "WHEN"
	case TokenTypeThen:
		return "THEN"
	case TokenTypeElse:
		return "ELSE"
	case TokenTypeEnd:
		return "END"
	case TokenTypeGroup:
		return "GROUP"
	case TokenTypeBy:
		return "BY"
	case TokenTypeHaving:
		return "HAVING"
	case TokenTypeOrder:
		return "ORDER"
	case TokenTypeAsc:
		return "ASC"
	case TokenTypeDesc:
		return "DESC"
	case TokenTypeLimit:
		return "LIMIT"
	case TokenTypeOffset:
		return "OFFSET"

	// DML Keywords
	case TokenTypeInsert:
		return "INSERT"
	case TokenTypeUpdate:
		return "UPDATE"
	case TokenTypeDelete:
		return "DELETE"
	case TokenTypeInto:
		return "INTO"
	case TokenTypeValues:
		return "VALUES"
	case TokenTypeSet:
		return "SET"

	// DDL Keywords
	case TokenTypeCreate:
		return "CREATE"
	case TokenTypeAlter:
		return "ALTER"
	case TokenTypeDrop:
		return "DROP"
	case TokenTypeTable:
		return "TABLE"
	case TokenTypeIndex:
		return "INDEX"
	case TokenTypeView:
		return "VIEW"
	case TokenTypeColumn:
		return "COLUMN"
	case TokenTypeDatabase:
		return "DATABASE"
	case TokenTypeSchema:
		return "SCHEMA"
	case TokenTypeTrigger:
		return "TRIGGER"

	// Aggregate functions
	case TokenTypeCount:
		return "COUNT"
	case TokenTypeSum:
		return "SUM"
	case TokenTypeAvg:
		return "AVG"
	case TokenTypeMin:
		return "MIN"
	case TokenTypeMax:
		return "MAX"

	// Compound keywords
	case TokenTypeGroupBy:
		return "GROUP_BY"
	case TokenTypeOrderBy:
		return "ORDER_BY"
	case TokenTypeLeftJoin:
		return "LEFT_JOIN"
	case TokenTypeRightJoin:
		return "RIGHT_JOIN"
	case TokenTypeInnerJoin:
		return "INNER_JOIN"
	case TokenTypeOuterJoin:
		return "OUTER_JOIN"
	case TokenTypeFullJoin:
		return "FULL_JOIN"
	case TokenTypeCrossJoin:
		return "CROSS_JOIN"

	// CTE and Set Operations
	case TokenTypeWith:
		return "WITH"
	case TokenTypeRecursive:
		return "RECURSIVE"
	case TokenTypeUnion:
		return "UNION"
	case TokenTypeExcept:
		return "EXCEPT"
	case TokenTypeIntersect:
		return "INTERSECT"
	case TokenTypeAll:
		return "ALL"

	// Window Function Keywords
	case TokenTypeOver:
		return "OVER"
	case TokenTypePartition:
		return "PARTITION"
	case TokenTypeRows:
		return "ROWS"
	case TokenTypeRange:
		return "RANGE"
	case TokenTypeUnbounded:
		return "UNBOUNDED"
	case TokenTypePreceding:
		return "PRECEDING"
	case TokenTypeFollowing:
		return "FOLLOWING"
	case TokenTypeCurrent:
		return "CURRENT"
	case TokenTypeRow:
		return "ROW"
	case TokenTypeGroups:
		return "GROUPS"
	case TokenTypeFilter:
		return "FILTER"
	case TokenTypeExclude:
		return "EXCLUDE"

	// Additional Join Keywords
	case TokenTypeCross:
		return "CROSS"
	case TokenTypeNatural:
		return "NATURAL"
	case TokenTypeFull:
		return "FULL"
	case TokenTypeUsing:
		return "USING"
	case TokenTypeLateral:
		return "LATERAL"

	// Constraint Keywords
	case TokenTypePrimary:
		return "PRIMARY"
	case TokenTypeKey:
		return "KEY"
	case TokenTypeForeign:
		return "FOREIGN"
	case TokenTypeReferences:
		return "REFERENCES"
	case TokenTypeUnique:
		return "UNIQUE"
	case TokenTypeCheck:
		return "CHECK"
	case TokenTypeDefault:
		return "DEFAULT"
	case TokenTypeAutoIncrement:
		return "AUTO_INCREMENT"
	case TokenTypeConstraint:
		return "CONSTRAINT"
	case TokenTypeNotNull:
		return "NOT_NULL"
	case TokenTypeNullable:
		return "NULLABLE"

	// Additional SQL Keywords
	case TokenTypeDistinct:
		return "DISTINCT"
	case TokenTypeExists:
		return "EXISTS"
	case TokenTypeAny:
		return "ANY"
	case TokenTypeSome:
		return "SOME"
	case TokenTypeCast:
		return "CAST"
	case TokenTypeConvert:
		return "CONVERT"
	case TokenTypeCollate:
		return "COLLATE"
	case TokenTypeCascade:
		return "CASCADE"
	case TokenTypeRestrict:
		return "RESTRICT"
	case TokenTypeReplace:
		return "REPLACE"
	case TokenTypeRename:
		return "RENAME"
	case TokenTypeTo:
		return "TO"
	case TokenTypeIf:
		return "IF"
	case TokenTypeOnly:
		return "ONLY"
	case TokenTypeFor:
		return "FOR"
	case TokenTypeNulls:
		return "NULLS"
	case TokenTypeFirst:
		return "FIRST"
	case TokenTypeLast:
		return "LAST"
	case TokenTypeFetch:
		return "FETCH"
	case TokenTypeNext:
		return "NEXT"

	// MERGE Statement Keywords
	case TokenTypeMerge:
		return "MERGE"
	case TokenTypeMatched:
		return "MATCHED"
	case TokenTypeTarget:
		return "TARGET"
	case TokenTypeSource:
		return "SOURCE"

	// Materialized View Keywords
	case TokenTypeMaterialized:
		return "MATERIALIZED"
	case TokenTypeRefresh:
		return "REFRESH"
	case TokenTypeTies:
		return "TIES"
	case TokenTypePercent:
		return "PERCENT"
	case TokenTypeTruncate:
		return "TRUNCATE"
	case TokenTypeReturning:
		return "RETURNING"

	// Row Locking Keywords
	case TokenTypeShare:
		return "SHARE"
	case TokenTypeNoWait:
		return "NOWAIT"
	case TokenTypeSkip:
		return "SKIP"
	case TokenTypeLocked:
		return "LOCKED"
	case TokenTypeOf:
		return "OF"

	// Grouping Set Keywords
	case TokenTypeGroupingSets:
		return "GROUPING_SETS"
	case TokenTypeRollup:
		return "ROLLUP"
	case TokenTypeCube:
		return "CUBE"
	case TokenTypeGrouping:
		return "GROUPING"
	case TokenTypeSets:
		return "SETS"
	case TokenTypeArray:
		return "ARRAY"
	case TokenTypeWithin:
		return "WITHIN"

	// Role/Permission Keywords
	case TokenTypeRole:
		return "ROLE"
	case TokenTypeUser:
		return "USER"
	case TokenTypeGrant:
		return "GRANT"
	case TokenTypeRevoke:
		return "REVOKE"
	case TokenTypePrivilege:
		return "PRIVILEGE"
	case TokenTypePassword:
		return "PASSWORD"
	case TokenTypeLogin:
		return "LOGIN"
	case TokenTypeSuperuser:
		return "SUPERUSER"
	case TokenTypeCreateDB:
		return "CREATEDB"
	case TokenTypeCreateRole:
		return "CREATEROLE"

	// Transaction Keywords
	case TokenTypeBegin:
		return "BEGIN"
	case TokenTypeCommit:
		return "COMMIT"
	case TokenTypeRollback:
		return "ROLLBACK"
	case TokenTypeSavepoint:
		return "SAVEPOINT"

	// Data Type Keywords
	case TokenTypeInt:
		return "INT"
	case TokenTypeInteger:
		return "INTEGER"
	case TokenTypeBigInt:
		return "BIGINT"
	case TokenTypeSmallInt:
		return "SMALLINT"
	case TokenTypeFloat:
		return "FLOAT"
	case TokenTypeDouble:
		return "DOUBLE"
	case TokenTypeDecimal:
		return "DECIMAL"
	case TokenTypeNumeric:
		return "NUMERIC"
	case TokenTypeVarchar:
		return "VARCHAR"
	case TokenTypeCharDataType:
		return "CHAR"
	case TokenTypeText:
		return "TEXT"
	case TokenTypeBoolean:
		return "BOOLEAN"
	case TokenTypeDate:
		return "DATE"
	case TokenTypeTime:
		return "TIME"
	case TokenTypeTimestamp:
		return "TIMESTAMP"
	case TokenTypeInterval:
		return "INTERVAL"
	case TokenTypeBlob:
		return "BLOB"
	case TokenTypeClob:
		return "CLOB"
	case TokenTypeJson:
		return "JSON"
	case TokenTypeUuid:
		return "UUID"

	// Special Token Types
	case TokenTypeIllegal:
		return "ILLEGAL"
	case TokenTypeAsterisk:
		return "*"
	case TokenTypeDoublePipe:
		return "||"
	case TokenTypeAdd:
		return "ADD"
	case TokenTypeNosuperuser:
		return "NOSUPERUSER"
	case TokenTypeNocreatedb:
		return "NOCREATEDB"
	case TokenTypeNocreaterole:
		return "NOCREATEROLE"
	case TokenTypeNologin:
		return "NOLOGIN"
	case TokenTypeValid:
		return "VALID"
	case TokenTypeDcproperties:
		return "DCPROPERTIES"
	case TokenTypeUrl:
		return "URL"
	case TokenTypeOwner:
		return "OWNER"
	case TokenTypeMember:
		return "MEMBER"
	case TokenTypeConnector:
		return "CONNECTOR"
	case TokenTypePolicy:
		return "POLICY"
	case TokenTypeUntil:
		return "UNTIL"
	case TokenTypeReset:
		return "RESET"
	case TokenTypeShow:
		return "SHOW"
	case TokenTypeDescribe:
		return "DESCRIBE"
	case TokenTypeExplain:
		return "EXPLAIN"

	default:
		return "TOKEN"
	}
}

// IsKeyword returns true if the token type is a SQL keyword.
// Uses range-based checking for O(1) performance (~0.24ns/op).
//
// Example:
//
//	if token.Type.IsKeyword() {
//	    // Handle SQL keyword token
//	}
func (t TokenType) IsKeyword() bool {
	// Use range constants for maintainability
	return (t >= TokenRangeKeywordStart && t < TokenRangeKeywordEnd &&
		t != TokenTypeAsterisk && t != TokenTypeDoublePipe && t != TokenTypeIllegal)
}

// IsOperator returns true if the token type is an operator.
// Uses range-based checking for O(1) performance.
//
// Example:
//
//	if token.Type.IsOperator() {
//	    // Handle operator token (e.g., +, -, *, /, etc.)
//	}
func (t TokenType) IsOperator() bool {
	// Use range constants for maintainability
	return (t >= TokenRangeOperatorStart && t < TokenRangeOperatorEnd) ||
		t == TokenTypeAsterisk || t == TokenTypeDoublePipe
}

// IsLiteral returns true if the token type is a literal value.
// Includes identifiers, numbers, strings, and boolean/null literals.
//
// Example:
//
//	if token.Type.IsLiteral() {
//	    // Handle literal value (identifier, number, string, true/false/null)
//	}
func (t TokenType) IsLiteral() bool {
	switch t {
	case TokenTypeIdentifier, TokenTypeNumber, TokenTypeString,
		TokenTypeSingleQuotedString, TokenTypeDoubleQuotedString,
		TokenTypeTrue, TokenTypeFalse, TokenTypeNull:
		return true
	}
	return false
}

// IsDMLKeyword returns true if the token type is a Data Manipulation Language keyword.
//
// Covered DML keywords: SELECT, INSERT, UPDATE, DELETE, INTO, VALUES, SET, FROM, WHERE.
//
// Example:
//
//	if token.Type.IsDMLKeyword() {
//	    // Handle DML keyword (SELECT, INSERT, UPDATE, DELETE, etc.)
//	}
func (t TokenType) IsDMLKeyword() bool {
	switch t {
	case TokenTypeSelect, TokenTypeInsert, TokenTypeUpdate, TokenTypeDelete,
		TokenTypeInto, TokenTypeValues, TokenTypeSet, TokenTypeFrom, TokenTypeWhere:
		return true
	}
	return false
}

// IsDDLKeyword returns true if the token type is a Data Definition Language keyword.
//
// Covered DDL keywords: CREATE, ALTER, DROP, TRUNCATE, TABLE, INDEX, VIEW, COLUMN,
// DATABASE, SCHEMA, TRIGGER.
//
// Example:
//
//	if token.Type.IsDDLKeyword() {
//	    // Handle DDL keyword (CREATE, ALTER, DROP, TABLE, etc.)
//	}
func (t TokenType) IsDDLKeyword() bool {
	switch t {
	case TokenTypeCreate, TokenTypeAlter, TokenTypeDrop, TokenTypeTruncate, TokenTypeTable,
		TokenTypeIndex, TokenTypeView, TokenTypeColumn, TokenTypeDatabase,
		TokenTypeSchema, TokenTypeTrigger:
		return true
	}
	return false
}

// IsJoinKeyword returns true if the token type is a JOIN-related keyword.
//
// Covered JOIN keywords: JOIN, INNER, LEFT, RIGHT, OUTER, CROSS, NATURAL, FULL,
// INNER JOIN, LEFT JOIN, RIGHT JOIN, OUTER JOIN, FULL JOIN, CROSS JOIN, ON, USING.
//
// Example:
//
//	if token.Type.IsJoinKeyword() {
//	    // Handle JOIN keyword (JOIN, INNER, LEFT, RIGHT, ON, USING, etc.)
//	}
func (t TokenType) IsJoinKeyword() bool {
	switch t {
	case TokenTypeJoin, TokenTypeInner, TokenTypeLeft, TokenTypeRight,
		TokenTypeOuter, TokenTypeCross, TokenTypeNatural, TokenTypeFull,
		TokenTypeInnerJoin, TokenTypeLeftJoin, TokenTypeRightJoin,
		TokenTypeOuterJoin, TokenTypeFullJoin, TokenTypeCrossJoin,
		TokenTypeOn, TokenTypeUsing:
		return true
	}
	return false
}

// IsWindowKeyword returns true if the token type is a window function keyword.
//
// Covered window keywords: OVER, PARTITION, ROWS, RANGE, UNBOUNDED, PRECEDING,
// FOLLOWING, CURRENT, ROW, GROUPS, FILTER, EXCLUDE.
//
// These keywords appear in window function specifications:
//
//	RANK() OVER (PARTITION BY dept ORDER BY salary ROWS UNBOUNDED PRECEDING)
//
// Example:
//
//	if token.Type.IsWindowKeyword() {
//	    // Handle window keyword (OVER, PARTITION BY, ROWS, RANGE, etc.)
//	}
func (t TokenType) IsWindowKeyword() bool {
	switch t {
	case TokenTypeOver, TokenTypePartition, TokenTypeRows, TokenTypeRange,
		TokenTypeUnbounded, TokenTypePreceding, TokenTypeFollowing,
		TokenTypeCurrent, TokenTypeRow, TokenTypeGroups, TokenTypeFilter,
		TokenTypeExclude:
		return true
	}
	return false
}

// IsAggregateFunction returns true if the token type is a standard SQL aggregate function.
//
// Covered aggregate functions: COUNT, SUM, AVG, MIN, MAX.
//
// Note: This method covers only the five standard SQL aggregate functions. Other
// aggregate functions (e.g., ARRAY_AGG, STRING_AGG, JSON_AGG) are represented as
// TokenTypeWord or TokenTypeIdentifier tokens.
//
// Example:
//
//	if token.Type.IsAggregateFunction() {
//	    // Handle aggregate function (COUNT, SUM, AVG, MIN, MAX)
//	}
func (t TokenType) IsAggregateFunction() bool {
	switch t {
	case TokenTypeCount, TokenTypeSum, TokenTypeAvg, TokenTypeMin, TokenTypeMax:
		return true
	}
	return false
}

// IsDataType returns true if the token type is a SQL data type.
// Uses range-based checking for O(1) performance.
//
// Example:
//
//	if token.Type.IsDataType() {
//	    // Handle data type token (INT, VARCHAR, BOOLEAN, etc.)
//	}
func (t TokenType) IsDataType() bool {
	// Use range constants for maintainability
	return t >= TokenRangeDataTypeStart && t < TokenRangeDataTypeEnd
}

// IsConstraint returns true if the token type is a table or column constraint keyword.
//
// Covered constraint keywords: PRIMARY, KEY, FOREIGN, REFERENCES, UNIQUE, CHECK,
// DEFAULT, AUTO_INCREMENT, CONSTRAINT, NOT NULL, NULLABLE.
//
// Example:
//
//	if token.Type.IsConstraint() {
//	    // Handle constraint keyword (PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK, etc.)
//	}
func (t TokenType) IsConstraint() bool {
	switch t {
	case TokenTypePrimary, TokenTypeKey, TokenTypeForeign, TokenTypeReferences,
		TokenTypeUnique, TokenTypeCheck, TokenTypeDefault, TokenTypeAutoIncrement,
		TokenTypeConstraint, TokenTypeNotNull, TokenTypeNullable:
		return true
	}
	return false
}

// IsSetOperation returns true if the token type is a set operation keyword.
//
// Covered set operations: UNION, EXCEPT, INTERSECT, ALL.
//
// These keywords combine multiple query result sets:
//
//	SELECT id FROM users UNION ALL SELECT id FROM admins
//	SELECT id FROM a EXCEPT SELECT id FROM b
//	SELECT id FROM a INTERSECT SELECT id FROM b
//
// Example:
//
//	if token.Type.IsSetOperation() {
//	    // Handle set operation keyword (UNION, EXCEPT, INTERSECT, ALL)
//	}
func (t TokenType) IsSetOperation() bool {
	switch t {
	case TokenTypeUnion, TokenTypeExcept, TokenTypeIntersect, TokenTypeAll:
		return true
	}
	return false
}
