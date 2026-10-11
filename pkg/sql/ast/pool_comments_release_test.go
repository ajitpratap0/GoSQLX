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

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestReleaseAST_ClearsComments checks that ReleaseAST zeroes the Comments
// backing array, so a pooled AST does not keep the previous input alive
// through Comment.Text substrings (#546).
func TestReleaseAST_ClearsComments(t *testing.T) {
	a := NewAST()
	a.Comments = append(a.Comments, models.Comment{Text: "-- x", Style: models.LineComment})
	backing := a.Comments[:cap(a.Comments)]

	ReleaseAST(a)

	for i, c := range backing {
		if c != (models.Comment{}) {
			t.Fatalf("Comments backing[%d] not zeroed after ReleaseAST: %+v", i, c)
		}
	}
}
