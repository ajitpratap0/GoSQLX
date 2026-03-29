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

// Package naming provides linter rules for SQL naming conventions and style.
//
// Rules:
//   - L024: Table alias required (multi-table queries)
//   - L025: Reserved keyword used as identifier
//   - L026: Implicit column list in INSERT
//   - L027: UNION instead of UNION ALL
//   - L028: Missing ORDER BY with LIMIT
//   - L029: Subquery in WHERE can be a JOIN
//   - L030: DISTINCT on many columns
package naming
