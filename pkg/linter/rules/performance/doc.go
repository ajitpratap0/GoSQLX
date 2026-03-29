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

// Package performance provides linter rules for detecting SQL anti-patterns
// that cause poor query performance, full table scans, or N+1 problems.
//
// Rules:
//   - L016: SELECT * (fetches all columns)
//   - L017: Missing WHERE on SELECT (full scan risk)
//   - L018: Leading wildcard LIKE (prevents index use)
//   - L019: NOT IN with subquery (NULL risk)
//   - L020: Correlated subquery in SELECT list (N+1)
//   - L021: OR instead of IN (multiple equality conditions)
//   - L022: Function on indexed column in WHERE
//   - L023: Implicit cross join (comma-separated tables)
package performance
