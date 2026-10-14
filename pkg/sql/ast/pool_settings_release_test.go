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

package ast

import "testing"

// TestReleaseSelectStatement_Settings verifies that releasing a
// SelectStatement releases and zeroes its ClickHouse SETTINGS entries so no
// stale Expression is retained by the pooled backing array (#600).
func TestReleaseSelectStatement_Settings(t *testing.T) {
	stmt := &SelectStatement{
		Settings: []QuerySetting{
			{Name: "max_threads", Value: &LiteralValue{Value: "4", Type: "INTEGER"}},
			{Name: "mode", Value: &Identifier{Name: "fast"}},
		},
	}
	releaseSelectStatement(stmt, releaseDrawn)
	if len(stmt.Settings) != 0 {
		t.Fatalf("len(Settings) = %d after release, want 0", len(stmt.Settings))
	}
	backing := stmt.Settings[:cap(stmt.Settings)]
	for i := range backing {
		if backing[i] != (QuerySetting{}) {
			t.Errorf("Settings backing slot %d not zeroed: %+v", i, backing[i])
		}
	}
}
