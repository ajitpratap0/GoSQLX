- **Version-2 query normalisation [W5-08]**: `fingerprint.Normalize`,
  `fingerprint.Fingerprint`, `gosqlx.Normalize` and `gosqlx.Fingerprint` now
  use the token-stream normal form. Fingerprints are `"v2:"` plus 64 lowercase
  hex characters (67 bytes); storage limited to `CHAR(64)` must be widened.
  Normalized text upper-cases keywords, drops alias
  `AS`, join `INNER`/`OUTER` and default `ASC`, redacts LIMIT/OFFSET, FETCH/TOP,
  typed literals and utility-statement literals, and collapses repeated normalized
  IN-list elements and VALUES rows, including question-mark placeholders.
  Keyword name parts next to a dot retain their source case, including `ASC`;
  other `ASC` tokens are dropped. With `Options.Dialect` set to `mysql`,
  `mariadb` or `bigquery`, double-quoted tokens follow the string-literal rules,
  including redaction and existing literal-alias exceptions. This deliberately
  coarsens MySQL/MariaDB `ANSI_QUOTES` identifiers. Default and `postgresql`
  dialects retain double-quoted identifier handling; legacy mode is unchanged.
  Session variables retain their spelling: `@@version` and `@@session.sql_mode`
  render without a space after `@@`.
  Tokenizable SQL with invalid syntax is accepted; call `gosqlx.Validate` first
  when syntax validation is required. Normalized text is a grouping key, not
  guaranteed to be parseable SQL. Parser limitations include implicit aliases
  without `AS` in RETURNING, projections, subqueries and view queries, redacted
  `SRID ?` values and transaction batches without statement separators.
  `AS` is retained in XMLATTRIBUTES and XMLFOREST.
  Grouping also differs for cast spelling,
  `IS TRUE` versus `IS FALSE`, quoted keyword names, clause order, redundant
  parentheses and content omitted by the legacy formatter. Version 2 also
  preserves the source case of bare identifier tokens in contextual grammar
  positions that the legacy formatter upper-cases: `SHOW server_version` and
  `SHOW SERVER_VERSION`, for example, produce different version-2 fingerprints
  but the same legacy fingerprint. Reproduce stored
  v1.17 fingerprints exactly with `fingerprint.FingerprintWithOptions(sql,
  fingerprint.Options{Mode: fingerprint.ModeLegacy})`; use
  `fingerprint.VersionOf` to distinguish versions. Recompute stored values or
  key on both versions during migration.
