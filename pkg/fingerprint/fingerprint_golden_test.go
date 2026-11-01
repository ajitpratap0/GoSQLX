// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
)

// TestGoldenFingerprint pins fingerprint.Normalize and fingerprint.Fingerprint
// for every benchmark corpus statement. Fingerprint values are a stored
// contract (callers key caches and slow-query groups on them), so they must
// never change silently. Regenerate with task goldens:update; inspect a
// mismatch with task goldens:diff.
func TestGoldenFingerprint(t *testing.T) {
	stmts := goldens.Corpus(t)
	g := goldens.New("fingerprint", "fingerprint.Normalize and fingerprint.Fingerprint per corpus statement", "normalize", "fingerprint")
	goldens.Parallel(len(stmts), func(i int) {
		st := stmts[i]
		g.Add(st.File, "normalize", st.Index, st.SQL, goldens.Safe(func() string {
			out, err := fingerprint.Normalize(st.SQL)
			if err != nil {
				return goldens.Error(err)
			}
			return out
		}))
		g.Add(st.File, "fingerprint", st.Index, st.SQL, goldens.Safe(func() string {
			out, err := fingerprint.Fingerprint(st.SQL)
			if err != nil {
				return goldens.Error(err)
			}
			return out
		}))
	})
	g.Check(t)
}
