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

func TestDialectTableExtensionsRelease(t *testing.T) {
	for _, mode := range []releaseMode{releaseDrawn, releaseAll} {
		t.Run(map[releaseMode]string{releaseDrawn: "drawn", releaseAll: "all"}[mode], func(t *testing.T) {
			sample := &SampleClause{Size: &LiteralValue{Value: "1", Type: "INTEGER"}, OffsetSize: &LiteralValue{Value: "2", Type: "INTEGER"}}
			releaseSampleClause(sample, mode)
			if sample.Size != nil || sample.OffsetSize != nil {
				t.Fatal("SAMPLE expressions retained after release")
			}
			pivot := &PivotClause{PivotExtensions: PivotExtensions{DefaultOnNull: &LiteralValue{Value: "0", Type: "INTEGER"}}}
			releasePivotExtensions(pivot, mode)
			if pivot.DefaultOnNull != nil {
				t.Fatal("DEFAULT ON NULL retained after release")
			}
			items := []RowsFromItem{{Function: &FunctionCall{Name: "f", Arguments: []Expression{&LiteralValue{Value: "1", Type: "INTEGER"}}}, Columns: &ColumnAliasList{Names: []string{"a"}, Types: []string{"int"}}}}
			ref := &TableReference{Modifiers: &TableModifiers{RowsFrom: items}}
			releaseTableFactorModifiers(ref, mode)
			if ref.Modifiers != nil || items[0].Function != nil || items[0].Columns != nil {
				t.Fatal("ROWS FROM retained after release")
			}
			joined := &TableReference{Modifiers: &TableModifiers{Sample: &SampleClause{Size: &LiteralValue{Value: "0.5", Type: "float"}}}}
			sampleOf := joined.Modifiers.Sample
			releaseTableFactorModifiers(joined, mode)
			if joined.Modifiers != nil || sampleOf.Size != nil {
				t.Fatal("joined-table SAMPLE retained after release")
			}
		})
	}
}
