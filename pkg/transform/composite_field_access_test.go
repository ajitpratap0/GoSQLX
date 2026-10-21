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

func TestCompositeFieldAccessTransforms(t *testing.T) {
	t.Run("qualify base column", func(t *testing.T) {
		stmt := mustParse(t, "SELECT (payload).name FROM users")
		if err := Apply(stmt, QualifyColumns("users")); err != nil {
			t.Fatal(err)
		}
		assertContains(t, format(stmt), "(users.payload).name")
	})
	t.Run("replace nested table", func(t *testing.T) {
		stmt := mustParse(t, "SELECT (SELECT payload FROM users).name")
		if err := Apply(stmt, ReplaceTable("users", "accounts")); err != nil {
			t.Fatal(err)
		}
		assertContains(t, format(stmt), "FROM accounts")
		assertNotContains(t, format(stmt), "FROM users")
	})
}
