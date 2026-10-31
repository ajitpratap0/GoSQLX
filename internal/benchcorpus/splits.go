// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package benchcorpus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// SplitsFile is the pinned split digest, relative to testdata/.
const SplitsFile = "bench/SPLITS.sha256"

// ExcludedLabel is the SPLITS line name for the known-failure exclusions.
const ExcludedLabel = "excluded"

// statementDigest hashes Key()+"\x00"+SQL+"\x00" over stmts in order.
func statementDigest(stmts []Statement) string {
	h := sha256.New()
	for _, st := range stmts {
		h.Write([]byte(st.Key()))
		h.Write([]byte{0})
		h.Write([]byte(st.SQL))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// BuildSplits renders one line per corpus (in Corpora order) plus one for the
// excluded statements: "<name> <statement count> <sha256>". MANIFEST.sha256
// pins the input bytes; this pins what gosqlx.SplitStatements and Load make of
// them, so a splitter change cannot silently change the benchmarked set.
func (s *Set) BuildSplits() string {
	var b strings.Builder
	for _, c := range Corpora {
		st := s.ByCorpus(c.Name)
		fmt.Fprintf(&b, "%s %d %s\n", c.Name, len(st), statementDigest(st))
	}
	ex := s.Excluded()
	fmt.Fprintf(&b, "%s %d %s\n", ExcludedLabel, len(ex), statementDigest(ex))
	return b.String()
}
