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

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestOptionSpecsAreRenderable checks that every option name the parser can
// store is on the renderers' allow-list, so no parsed option is silently
// dropped by the formatter.
func TestOptionSpecsAreRenderable(t *testing.T) {
	for _, specs := range [][]optionSpec{tableOptionSpecs, indexOptionSpecs, mvEngineOptionSpecs} {
		for _, s := range specs {
			name := strings.Join(s.words, " ")
			if ast.TableOptionNameText(name) != name {
				t.Errorf("option %q is parsed but not on the TableOptionNameText allow-list", name)
			}
		}
	}
}
