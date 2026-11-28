// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestGoldenFingerprint pins fingerprint.Normalize and fingerprint.Fingerprint
// for every benchmark corpus statement. Fingerprint values are a stored
// contract (callers key caches and slow-query groups on them), so they must
// never change silently. After the equivalence tests pass, regenerate only
// this golden with go test ./pkg/fingerprint -run TestGoldenFingerprint
// -goldens.update, and compare the legacy columns with origin/main. Inspect
// a mismatch with task goldens:diff.
func TestGoldenFingerprint(t *testing.T) {
	stmts := goldens.Corpus(t)
	g := goldens.New("fingerprint", "legacy and v2 normalization and fingerprints per corpus statement", "legacy_normalize", "legacy_fingerprint", "normalize", "fingerprint", "normalize_dialect")
	goldens.Parallel(len(stmts), func(i int) {
		st := stmts[i]
		d := keywords.SQLDialect(st.Dialect)
		if st.Dialect == benchcorpus.GenericDialect {
			d = ""
		}
		for _, cell := range []struct {
			column  string
			mode    fingerprint.Mode
			dialect keywords.SQLDialect
			hash    bool
		}{
			{"legacy_normalize", fingerprint.ModeLegacy, "", false},
			{"legacy_fingerprint", fingerprint.ModeLegacy, "", true},
			{"normalize", fingerprint.ModeTokens, "", false},
			{"fingerprint", fingerprint.ModeTokens, "", true},
			{"normalize_dialect", fingerprint.ModeTokens, d, false},
		} {
			g.Add(st.File, cell.column, st.Index, st.SQL, goldens.Safe(func() string {
				opts := fingerprint.Options{Mode: cell.mode, Dialect: cell.dialect}
				var out string
				var err error
				if cell.hash {
					out, err = fingerprint.FingerprintWithOptions(st.SQL, opts)
				} else {
					out, err = fingerprint.NormalizeWithOptions(st.SQL, opts)
				}
				if err != nil {
					return goldens.Error(err)
				}
				return out
			}))
		}
	})
	g.Check(t)
}
