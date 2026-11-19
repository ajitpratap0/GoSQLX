// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"errors"
	"fmt"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Mode selects the normalization algorithm.
type Mode uint8

const (
	// ModeTokens is the default token-stream normal form, with version-2 fingerprints.
	ModeTokens Mode = iota
	// ModeLegacy selects the v1.17 parse-and-format normal form and unprefixed fingerprints.
	ModeLegacy
)

// Options selects the normalization algorithm and SQL dialect.
type Options struct {
	Mode Mode
	// Dialect defaults to PostgreSQL when empty, matching v1.17.
	Dialect keywords.SQLDialect
}

// Version is the normal-form version produced by ModeTokens.
const Version = 2

// VersionPrefix prefixes every ModeTokens fingerprint.
const VersionPrefix = "v2:"

// ErrEmpty means that no SQL statement token remains after tokenization.
var ErrEmpty = errors.New("fingerprint: no SQL statement")

func (o Options) validate() error {
	if o.Mode != ModeTokens && o.Mode != ModeLegacy {
		return fmt.Errorf("fingerprint: unknown mode %d", o.Mode)
	}
	if o.Dialect != "" && !keywords.IsValidDialect(string(o.Dialect)) {
		return fmt.Errorf("fingerprint: unsupported dialect %q", o.Dialect)
	}
	return nil
}

// VersionOf reports 2 for a valid version-2 fingerprint, 1 for a valid
// unprefixed legacy fingerprint, and 0 otherwise. Hexadecimal must be lowercase.
func VersionOf(fp string) int {
	version := 1
	if len(fp) == len(VersionPrefix)+64 && fp[:len(VersionPrefix)] == VersionPrefix {
		version = Version
		fp = fp[len(VersionPrefix):]
	}
	if len(fp) != 64 {
		return 0
	}
	for i := 0; i < len(fp); i++ {
		c := fp[i]
		if !('0' <= c && c <= '9') && !('a' <= c && c <= 'f') {
			return 0
		}
	}
	return version
}
