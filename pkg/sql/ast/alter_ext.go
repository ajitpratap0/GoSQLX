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

// Sub-actions of ALTER COLUMN beyond SET/DROP DEFAULT and SET/DROP NOT NULL.
// They continue the AlterColumnOperation sequence declared in types.go.
const (
	// AlterColumnSetDataType is [SET DATA] TYPE t [USING expr]; the spelling is
	// kept in AlterTableOperation.Keyword.
	AlterColumnSetDataType AlterColumnOperation = iota + 100
	// AlterColumnOther is any other sub-action (SET MASKING POLICY p,
	// SET STATISTICS n, DROP IDENTITY, ...), kept as AlterTableOperation.Keyword
	// and AlterTableOperation.Text.
	AlterColumnOther
)

// extChildren returns the expression children contributed by the extended
// ALTER TABLE fields.
func (a *AlterTableOperation) extChildren() []Node {
	var children []Node
	if a.DefaultValue != nil {
		children = append(children, a.DefaultValue)
	}
	if a.Using != nil {
		children = append(children, a.Using)
	}
	for i := range a.Assignments {
		children = append(children, &a.Assignments[i])
	}
	if a.PartitionExpr != nil {
		children = append(children, a.PartitionExpr)
	}
	if a.Where != nil {
		children = append(children, a.Where)
	}
	if a.Partitioning != nil {
		children = append(children, a.Partitioning)
	}
	for i := range a.PartitionDefinitions {
		children = append(children, &a.PartitionDefinitions[i])
	}
	for _, name := range a.PartitionNames {
		children = append(children, name)
	}
	if a.PartitionCount != nil {
		children = append(children, a.PartitionCount)
	}
	return children
}
