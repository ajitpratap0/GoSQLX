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

func TestQueryTailPreservesTies(t *testing.T) {
	limit := 5
	for _, fetch := range []bool{false, true} {
		s := &SelectStatement{Limit: &limit, Extras: &SelectExtras{LimitWithTies: true}}
		if fetch {
			s.Limit = nil
			s.Extras = nil
			s.Fetch = &FetchClause{WithTies: true}
		}
		tail := QueryTailFrom(s)
		view := tail.Select()
		if fetch {
			if view.Fetch == nil || !view.Fetch.WithTies {
				t.Fatal("FETCH ties lost")
			}
		} else if !view.DialectExtras().LimitWithTies {
			t.Fatal("LIMIT ties lost")
		}
		again := QueryTailFrom(view).Select()
		if fetch {
			if again.Fetch == nil || !again.Fetch.WithTies {
				t.Fatal("FETCH ties lost after round trip")
			}
		} else if !again.DialectExtras().LimitWithTies {
			t.Fatal("LIMIT ties lost after round trip")
		}
	}
}
