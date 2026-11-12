- **Version-2 query normalisation [W5-08]**: `fingerprint.Normalize`,
  `fingerprint.Fingerprint`, `gosqlx.Normalize` and `gosqlx.Fingerprint` now
  use the token-stream normal form. Fingerprints are `"v2:"` plus 64 lowercase
  hex characters (67 bytes); storage limited to `CHAR(64)` must be widened.
  Normalized text upper-cases keywords, drops alias
  `AS`, join `INNER`/`OUTER` and default `ASC`, redacts LIMIT/OFFSET, FETCH/TOP,
  typed literals and utility-statement literals, and collapses repeated normalized
  IN-list elements and VALUES rows, including question-mark placeholders.
  Keyword name parts next to a dot retain their source case, including `ASC`;
  other `ASC` tokens are dropped.
  Tokenizable SQL with invalid syntax is accepted; call `gosqlx.Validate` first
  when syntax validation is required. Normalized text is a grouping key, not
  guaranteed to be parseable SQL: the symmetric reparse oracle tracks 46 corpus
  cases, including 44 in the implicit-alias parser gap (follow-up F1) for aliases
  without `AS` in RETURNING, projections, subqueries and view queries, plus one
  redacted `SRID ?` value and one transaction batch without statement separators.
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
