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

// Package safety provides linter rules for detecting dangerous SQL operations
// that can cause irreversible data loss or security vulnerabilities.
//
// Rules:
//   - L011: DELETE without WHERE clause
//   - L012: UPDATE without WHERE clause
//   - L013: DROP without IF EXISTS
//   - L014: TRUNCATE TABLE warning
//   - L015: SELECT INTO OUTFILE/DUMPFILE
package safety
