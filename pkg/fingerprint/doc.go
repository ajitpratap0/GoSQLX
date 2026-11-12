// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Package fingerprint provides SQL normalization and SHA-256 fingerprints.
//
// The default ModeTokens uses normal form version 2: keywords become uppercase,
// data literals become question marks, redundant aliases and join modifiers
// disappear, and repeated IN elements and VALUES rows collapse. Keyword name
// parts adjacent to a dot retain their case, including ASC; only other ASC
// tokens are dropped. Identifier case, placeholders and structurally significant
// literals are retained. Delimited names keep any quotes needed to preserve
// their meaning in the selected dialect. With Options.Dialect set to mysql,
// mariadb or bigquery, double-quoted tokens follow the string-literal rules,
// including redaction and existing literal-alias exceptions. This deliberately
// coarsens ANSI_QUOTES identifiers in MySQL and MariaDB. Default and PostgreSQL
// dialects retain double-quoted identifier handling; legacy mode is unchanged.
// Session variables retain their spelling, including @@version and
// @@session.sql_mode.
// Redaction includes LIMIT/OFFSET, FETCH/TOP, typed literals and utility
// statements; repeated question-mark placeholders also collapse in IN lists
// and VALUES rows. Normalized text is a grouping key, not guaranteed to be
// parseable SQL. Parser limitations include implicit aliases without AS in
// RETURNING, projections, subqueries and view queries, redacted SRID values,
// and transaction batches without statement separators. Placeholders in
// positions such as LIMIT ? can also prevent parsing. All normalization rules
// apply at every nesting depth, including beyond 32 frames; the frame stack
// grows as needed.
// Token-stream normalization reports lexical errors, but does not validate SQL
// syntax. Callers that require syntax validation should validate SQL separately.
//
// Version-2 fingerprints consist of "v2:" and 64 lowercase hexadecimal SHA-256
// characters (67 bytes, requiring wider storage than CHAR(64)). VersionOf
// distinguishes them from the unprefixed legacy values.
// For migration, ModeLegacy with an empty Options.Dialect reproduces the v1.17
// parse-and-format normal form and fingerprint byte for byte. Either recompute
// stored fingerprints or use both versions during a transition. Explicit
// dialects are supported in both modes, but legacy dialect-specific values have
// no v1.17 compatibility guarantee.
//
// Grouping can split queries that legacy treats as equivalent when its formatter
// upper-cases bare identifier tokens in contextual grammar positions. For
// example, SHOW server_version and SHOW SERVER_VERSION have different version-2
// fingerprints because identifier case is preserved; their legacy fingerprints
// are equal.
package fingerprint
