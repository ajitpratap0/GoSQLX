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

package schema

import (
	"strings"
	"testing"
)

// TestValidator_JoinUsingColumns_Issue603 checks that the columns of
// JOIN ... USING (cols) are still validated now that the parser stores them
// in JoinClause.Using instead of Condition (#603).
func TestValidator_JoinUsingColumns_Issue603(t *testing.T) {
	s := NewSchema("testdb")
	a := NewTable("a")
	a.AddColumn(&Column{Name: "id", DataType: "INT"})
	a.AddColumn(&Column{Name: "k", DataType: "INT"})
	s.AddTable(a)
	b := NewTable("b")
	b.AddColumn(&Column{Name: "id", DataType: "INT"})
	b.AddColumn(&Column{Name: "k", DataType: "INT"})
	s.AddTable(b)
	v := NewValidator(s)

	columnErrors := func(t *testing.T, sql string) []string {
		t.Helper()
		errs, err := v.Validate(sql)
		if err != nil {
			t.Fatalf("Validate(%q): %v", sql, err)
		}
		var msgs []string
		for _, e := range errs {
			if e.Severity == "error" {
				msgs = append(msgs, e.Message)
			}
		}
		return msgs
	}

	if msgs := columnErrors(t, "SELECT * FROM a JOIN b USING (id)"); len(msgs) != 0 {
		t.Errorf("valid USING column reported errors: %v", msgs)
	}
	if msgs := columnErrors(t, "SELECT * FROM a JOIN b USING (id, k)"); len(msgs) != 0 {
		t.Errorf("valid multi-column USING reported errors: %v", msgs)
	}

	for _, sql := range []string{
		"SELECT * FROM a JOIN b USING (zz)",
		"SELECT * FROM a JOIN b USING (id, zz)",
	} {
		msgs := columnErrors(t, sql)
		found := false
		for _, m := range msgs {
			if strings.Contains(m, `"zz"`) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: expected a column-not-found error for zz, got %v", sql, msgs)
		}
	}
}
