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

// Keyword represents a SQL keyword with its properties and reservation status.
//
// Each keyword has multiple attributes that determine how it can be used:
//   - Word: The keyword string (e.g., "SELECT", "LATERAL")
//   - Type: The token type assigned to this keyword (models.TokenType)
//   - Reserved: Whether the keyword is reserved and cannot be used as an identifier
//   - ReservedForTableAlias: Whether the keyword cannot be used as a table alias
//
// Example:
//
//	selectKeyword := Keyword{
//	    Word:                  "SELECT",
//	    Type:                  models.TokenTypeSelect,
//	    Reserved:              true,
//	    ReservedForTableAlias: true,
//	}
//
//	rankFunction := Keyword{
//	    Word:                  "RANK",
//	    Type:                  models.TokenTypeKeyword,
//	    Reserved:              false,  // Window function names are non-reserved
//	    ReservedForTableAlias: false,
//	}
type Keyword struct {
	Word                  string           // The keyword string (uppercase normalized)
	Type                  models.TokenType // Token type for this keyword
	Reserved              bool             // True if keyword cannot be used as identifier
	ReservedForTableAlias bool             // True if keyword cannot be used as table alias
}
