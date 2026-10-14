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

// ReservedNameWordsForTest returns a copy of reservedNameWords for the
// external guard test in package ast_test.
func ReservedNameWordsForTest() map[string]bool {
	m := make(map[string]bool, len(reservedNameWords))
	for k, v := range reservedNameWords {
		m[k] = v
	}
	return m
}

// KeywordFunctionNamesForTest returns a copy of keywordFunctionNames for the
// external guard test in package ast_test.
func KeywordFunctionNamesForTest() map[string]bool {
	m := make(map[string]bool, len(keywordFunctionNames))
	for k, v := range keywordFunctionNames {
		m[k] = v
	}
	return m
}

// ConstraintNameWordsForTest returns a copy of constraintNameWords for the
// external guard test in package ast_test.
func ConstraintNameWordsForTest() map[string]bool {
	m := make(map[string]bool, len(constraintNameWords))
	for k, v := range constraintNameWords {
		m[k] = v
	}
	return m
}
