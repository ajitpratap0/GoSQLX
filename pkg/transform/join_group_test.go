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

package transform

import "testing"

// TestReplaceTable_InsideJoinGroup checks that ReplaceTable reaches the tables
// and join conditions inside a parenthesized join group.
func TestReplaceTable_InsideJoinGroup(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM a LEFT JOIN (users JOIN c ON users.id = c.uid) ON a.id = users.aid")
	if err := Apply(stmt, ReplaceTable("users", "accounts")); err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "(accounts INNER JOIN c ON accounts.id = c.uid) ON a.id = accounts.aid")
	assertNotContains(t, out, "users")
}
