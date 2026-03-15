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

import (
	"testing"
)

func TestSetLimit(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetLimit(10))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "LIMIT")
	assertContains(t, out, "10")
}

func TestSetOffset(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetOffset(20))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "OFFSET")
	assertContains(t, out, "20")
}

func TestRemoveLimit(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users LIMIT 10")
	err := Apply(stmt, RemoveLimit())
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertNotContains(t, out, "LIMIT")
}

func TestRemoveOffset(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users LIMIT 10 OFFSET 5")
	err := Apply(stmt, RemoveOffset())
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertNotContains(t, out, "OFFSET")
}

func TestSetLimit_ReplaceExisting(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users LIMIT 5")
	err := Apply(stmt, SetLimit(100))
	if err != nil {
		t.Fatal(err)
	}
	out := format(stmt)
	assertContains(t, out, "100")
}

func TestLimit_UnsupportedStatement(t *testing.T) {
	stmt := mustParse(t, "DELETE FROM users")
	err := Apply(stmt, SetLimit(10))
	if err == nil {
		t.Fatal("expected error for DELETE")
	}
}

func TestSetLimit_Negative(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetLimit(-1))
	if err == nil {
		t.Fatal("expected error for negative limit")
	}
}

func TestSetLimit_NegativeLarge(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetLimit(-100))
	if err == nil {
		t.Fatal("expected error for negative limit")
	}
}

func TestSetLimit_Zero(t *testing.T) {
	// LIMIT 0 is valid SQL - returns an empty result set.
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetLimit(0))
	if err != nil {
		t.Fatalf("SetLimit(0) should succeed: %v", err)
	}
	out := format(stmt)
	assertContains(t, out, "LIMIT")
	assertContains(t, out, "0")
}

func TestSetOffset_Zero(t *testing.T) {
	// OFFSET 0 is valid SQL - no offset applied.
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetOffset(0))
	if err != nil {
		t.Fatalf("SetOffset(0) should succeed: %v", err)
	}
	out := format(stmt)
	assertContains(t, out, "OFFSET")
	assertContains(t, out, "0")
}

func TestSetOffset_Negative(t *testing.T) {
	stmt := mustParse(t, "SELECT * FROM users")
	err := Apply(stmt, SetOffset(-5))
	if err == nil {
		t.Fatal("expected error for negative offset")
	}
}
