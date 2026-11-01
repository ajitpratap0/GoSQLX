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

package benchcorpus

import (
	"fmt"
	"strconv"
	"strings"
)

// Scale shapes accepted by ScaleSQL. Each grows linearly in one dimension so
// that a benchmark over {10, 100, 1000} exposes super-linear behaviour.
const (
	// ScaleWide is a SELECT with n computed columns.
	ScaleWide = "wide"
	// ScaleIn is a SELECT whose WHERE holds an IN list of n integers.
	ScaleIn = "in"
	// ScaleValues is an INSERT of n literal rows.
	ScaleValues = "values"
	// ScaleAnd is a SELECT whose WHERE is a chain of n ANDed comparisons.
	ScaleAnd = "and"
)

// ScaleShapes lists every shape ScaleSQL accepts, in benchmark-name order.
var ScaleShapes = []string{ScaleWide, ScaleIn, ScaleValues, ScaleAnd}

// ScaleSizes are the n values used by the scale benchmarks.
var ScaleSizes = []int{10, 100, 1000}

// ScaleSQL returns the deterministic SQL text for shape at size n (n >= 1).
// It panics on an unknown shape or n < 1, which is a benchmark programming
// error rather than a runtime condition.
func ScaleSQL(shape string, n int) string {
	if n < 1 {
		panic(fmt.Sprintf("benchcorpus: ScaleSQL n=%d, want >= 1", n))
	}
	parts := make([]string, n)
	switch shape {
	case ScaleWide:
		for i := range parts {
			parts[i] = fmt.Sprintf("t.col_%d + %d AS c%d", i, i, i)
		}
		return "SELECT " + strings.Join(parts, ", ") + " FROM t WHERE t.a = 1"
	case ScaleIn:
		for i := range parts {
			parts[i] = strconv.Itoa(i * 7)
		}
		return "SELECT id FROM t WHERE id IN (" + strings.Join(parts, ", ") + ")"
	case ScaleValues:
		for i := range parts {
			parts[i] = fmt.Sprintf("(%d, 'name_%d', %d.5)", i, i, i)
		}
		return "INSERT INTO t (a, b, c) VALUES " + strings.Join(parts, ", ")
	case ScaleAnd:
		for i := range parts {
			parts[i] = fmt.Sprintf("x%d = %d", i, i)
		}
		return "SELECT id FROM t WHERE " + strings.Join(parts, " AND ")
	}
	panic(fmt.Sprintf("benchcorpus: unknown scale shape %q", shape))
}
