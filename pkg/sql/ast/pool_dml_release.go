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

// releaseDMLTargetFields releases the expressions reachable from the UPDATE /
// DELETE dialect fields and zeroes them.
func releaseDMLTargetFields(d *DMLTargetFields, mode releaseMode) {
	if d.Top != nil {
		releaseExpression(d.Top.Count, mode)
	}
	for i := range d.Tables {
		releaseTableReference(&d.Tables[i], mode)
	}
	// Join Lefts are value copies of a target (see releaseSelectStatement);
	// only Right, Condition and Using are owned by the join.
	for i := range d.Joins {
		releaseTableReference(&d.Joins[i].Right, mode)
		releaseExpression(d.Joins[i].Condition, mode)
		for _, u := range d.Joins[i].Using {
			releaseExpression(u, mode)
		}
	}
	for _, e := range d.Output {
		releaseExpression(e, mode)
	}
	if d.OutputInto != nil {
		for _, e := range d.OutputInto.Columns {
			releaseExpression(e, mode)
		}
	}
	for i := range d.OrderBy {
		releaseExpression(d.OrderBy[i].Expression, mode)
	}
	releaseExpression(d.Limit, mode)
	for _, e := range d.ReturningInto {
		releaseExpression(e, mode)
	}
	if d.History != nil {
		for _, partition := range d.History.Partitions {
			releaseExpression(partition, mode)
		}
	}
	*d = DMLTargetFields{}
}

// releaseInsertDialectFields releases the expressions reachable from the
// INSERT dialect fields and zeroes them.
func releaseInsertDialectFields(d *InsertDialectFields, mode releaseMode) {
	if d.Top != nil {
		releaseExpression(d.Top.Count, mode)
	}
	if d.OutputInto != nil {
		for _, e := range d.OutputInto.Columns {
			releaseExpression(e, mode)
		}
	}
	for _, e := range d.ReturningInto {
		releaseExpression(e, mode)
	}
	if d.TableFunction != nil {
		releaseExpression(d.TableFunction, mode)
	}
	for i := range d.Settings {
		releaseExpression(d.Settings[i].Value, mode)
	}
	if m := d.MultiTable; m != nil {
		for i := range m.Branches {
			b := &m.Branches[i]
			releaseExpression(b.When, mode)
			for j := range b.Into {
				for _, e := range b.Into[j].Columns {
					releaseExpression(e, mode)
				}
				for _, e := range b.Into[j].Values {
					releaseExpression(e, mode)
				}
			}
		}
	}
	if d.LogErrors != nil {
		releaseExpression(d.LogErrors.Tag, mode)
	}
	*d = InsertDialectFields{}
}
