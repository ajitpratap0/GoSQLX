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

package keywords

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// IsCompoundKeyword checks if a string is a compound keyword
func (k *Keywords) IsCompoundKeyword(s string) bool {
	_, ok := k.CompoundKeywords[s]
	return ok
}

// GetCompoundKeywordType returns the token type for a compound keyword
func (k *Keywords) GetCompoundKeywordType(s string) (models.TokenType, bool) {
	t, ok := k.CompoundKeywords[s]
	return t, ok
}
