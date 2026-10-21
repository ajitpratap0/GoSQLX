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

package keywords_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestDialectNames(t *testing.T) {
	names := keywords.DialectNames()
	all := keywords.AllDialects()
	if len(names) != len(all) {
		t.Fatalf("DialectNames() has %d entries, AllDialects() has %d", len(names), len(all))
	}
	seen := make(map[string]bool, len(names))
	for i, name := range names {
		if name != string(all[i]) {
			t.Errorf("DialectNames()[%d] = %q, want %q (same order as AllDialects)", i, name, all[i])
		}
		if !keywords.IsValidDialect(name) {
			t.Errorf("DialectNames() entry %q rejected by IsValidDialect", name)
		}
		if name == string(keywords.DialectUnknown) || name == "" {
			t.Errorf("DialectNames() must not contain %q", name)
		}
		if seen[name] {
			t.Errorf("DialectNames() contains duplicate %q", name)
		}
		seen[name] = true
	}

	// The returned slice is a fresh copy; mutating it must not affect later calls.
	names[0] = "mutated"
	if keywords.DialectNames()[0] == "mutated" {
		t.Error("DialectNames() returned a shared slice")
	}
}
