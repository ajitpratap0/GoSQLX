// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"crypto/sha256"
	"fmt"
)

// Normalize returns the version-2 token-stream normal form of sql.
// It reports tokenization errors but does not validate SQL syntax.
// Use NormalizeWithOptions with ModeLegacy for the v1.17 normal form.
func Normalize(sql string) (string, error) {
	return NormalizeWithOptions(sql, Options{})
}

// Fingerprint returns VersionPrefix followed by the lowercase SHA-256 digest
// of Normalize(sql). It does not validate SQL syntax.
func Fingerprint(sql string) (string, error) {
	return FingerprintWithOptions(sql, Options{})
}

// NormalizeWithOptions normalizes sql using the selected algorithm and dialect.
// ModeLegacy with an empty dialect reproduces the v1.17 output byte for byte.
// Explicit dialects have no corresponding v1.17 compatibility guarantee.
func NormalizeWithOptions(sql string, opts Options) (string, error) {
	if err := opts.validate(); err != nil {
		return "", err
	}
	if opts.Mode == ModeLegacy {
		return normalizeLegacy(sql, opts.Dialect)
	}
	return normalizeTokens(sql, opts, false)
}

// FingerprintWithOptions fingerprints sql using the selected algorithm and
// dialect. ModeTokens produces a version-2 fingerprint with VersionPrefix;
// ModeLegacy produces an unprefixed 64-character lowercase SHA-256 digest.
// Only ModeLegacy with an empty dialect reproduces v1.17 values byte for byte.
func FingerprintWithOptions(sql string, opts Options) (string, error) {
	if err := opts.validate(); err != nil {
		return "", err
	}
	if opts.Mode == ModeTokens {
		return normalizeTokens(sql, opts, true)
	}
	normalized, err := normalizeLegacy(sql, opts.Dialect)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("%x", h), nil
}
