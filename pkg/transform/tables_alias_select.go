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

import "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"

// addAliasToSelect shares DML's binding checks and scope-aware qualifier rewrite.
func addAliasToSelect(s *ast.SelectStatement, tableName, alias string) error {
	refs := dmlAliasTargets{tableName: tableName, alias: alias}
	refs.list(s.From)
	refs.joins(s.Joins)
	if err := refs.check(); err != nil {
		return err
	}
	if err := refs.checkCaptures(s); err != nil {
		return err
	}
	refs.apply()
	// Only nested SELECT nodes establish a new scope for this rewrite.
	for _, child := range s.Children() {
		rewriteAliasQualifiers(child, refs.matched, alias)
	}
	return nil
}
