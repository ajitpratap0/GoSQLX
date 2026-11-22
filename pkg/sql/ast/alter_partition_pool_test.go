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

func TestAlterPartitionReleaseModes(t *testing.T) {
	for _, mode := range []releaseMode{releaseDrawn, releaseAll} {
		for _, legacy := range []bool{false, true} {
			leaf := &LiteralValue{Value: int64(2030)}
			array := GetArrayConstructor()
			array.Elements = []Expression{leaf}
			key := &Identifier{Name: "year"}
			part := &PartitionBy{Type: "RANGE", Expressions: []Expression{key}}
			op := &AlterTableOperation{Type: AlterPartitioning, Partitioning: part, PartitionDefinitions: []PartitionDefinition{{Name: "p", LessThan: array}}, PartitionNames: []*Ident{{Name: "old"}}, PartitionCount: &LiteralValue{Value: "2", Type: "int"}}
			stmt := GetAlterStatement()
			stmt.Operation = op
			if !legacy {
				stmt.Operations = []AlterOperation{op}
			}
			releaseAlterStatement(stmt, mode)
			if op.Partitioning != nil || op.PartitionDefinitions != nil || op.PartitionNames != nil || op.PartitionCount != nil {
				t.Fatalf("mode %v legacy %v: partition fields not cleared", mode, legacy)
			}
			if len(array.Elements) != 0 {
				t.Errorf("mode %v: pooled array not released", mode)
			}
			if mode == releaseAll {
				if leaf.Value != nil || key.Name != "" {
					t.Error("releaseAll did not clear leaves")
				}
			} else if leaf.Value != int64(2030) || key.Name != "year" {
				t.Error("releaseDrawn reset undrawn leaves")
			}
		}
	}
}
