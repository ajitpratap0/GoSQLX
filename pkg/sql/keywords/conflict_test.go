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

package keywords

import (
	"strings"
	"testing"
)

// TestKeywords_NoConflicts_AllDialects verifies that constructing a Keywords
// instance for every supported dialect produces zero keyword-registration
// conflicts. A conflict is recorded whenever two different keyword sources
// (for example ADDITIONAL_KEYWORDS and SQLITE_SPECIFIC) register the same
// word with a different Type, Reserved, or ReservedForTableAlias value; the
// first registration wins at runtime, so a conflict silently hides the
// intended dialect-specific classification.
//
// If this test fails, look at the reported conflicts and move the
// dialect-specific keyword out of the shared ADDITIONAL_KEYWORDS list (or
// intentionally align the two records so they are equivalent).
func TestKeywords_NoConflicts_AllDialects(t *testing.T) {
	dialects := []SQLDialect{
		DialectGeneric,
		DialectPostgreSQL,
		DialectMySQL,
		DialectMariaDB,
		DialectSQLServer,
		DialectOracle,
		DialectSQLite,
		DialectSnowflake,
		DialectBigQuery,
		DialectRedshift,
		DialectClickHouse,
	}

	for _, d := range dialects {
		d := d
		t.Run(string(d), func(t *testing.T) {
			_ = New(d, true)
			c := Conflicts()
			if len(c) == 0 {
				return
			}
			var lines []string
			for _, conflict := range c {
				lines = append(lines, conflict.String())
			}
			t.Errorf("dialect %s has %d keyword conflicts:\n  %s",
				d, len(c), strings.Join(lines, "\n  "))
		})
	}
}

// TestKeywords_Conflicts_ResetBetweenConstructions verifies that each call to
// New() starts from a clean conflict slate. A previous dialect with
// conflicts must not leak into the next construction's Conflicts() view.
func TestKeywords_Conflicts_ResetBetweenConstructions(t *testing.T) {
	// Run two constructions back-to-back and confirm the second one's
	// Conflicts() reflects only its own state (not an accumulation).
	_ = New(DialectSQLite, true)
	first := len(Conflicts())

	_ = New(DialectGeneric, true)
	second := len(Conflicts())

	if second > first {
		t.Fatalf("Conflicts() should be reset between New() calls; first=%d second=%d", first, second)
	}
}

// TestKeywords_ResetConflicts verifies the ResetConflicts helper clears state.
func TestKeywords_ResetConflicts(t *testing.T) {
	// Construct a dialect that historically has had conflicts; even if it
	// has none now, the reset should still produce an empty slice.
	_ = New(DialectSQLite, true)
	ResetConflicts()
	if c := Conflicts(); len(c) != 0 {
		t.Fatalf("Conflicts() after ResetConflicts() should be empty, got %d entries", len(c))
	}
}

// TestKeywords_Conflict_StringFormat exercises the String() representation
// so a failure message is readable when a conflict is reported.
func TestKeywords_Conflict_StringFormat(t *testing.T) {
	c := KeywordConflict{
		Word:      "EXAMPLE",
		Existing:  Keyword{Word: "EXAMPLE", Reserved: true, ReservedForTableAlias: false},
		Attempted: Keyword{Word: "EXAMPLE", Reserved: false, ReservedForTableAlias: false},
		Dialect:   DialectGeneric,
	}
	s := c.String()
	for _, want := range []string{"EXAMPLE", "existing", "attempted", "dialect=generic"} {
		if !strings.Contains(s, want) {
			t.Errorf("KeywordConflict.String() = %q, want substring %q", s, want)
		}
	}
}
