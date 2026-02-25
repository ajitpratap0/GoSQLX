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

import (
	"fmt"
	"log"
	"strings"
)

func (k *Keywords) AddKeyword(keyword Keyword) error {
	upperWord := strings.ToUpper(keyword.Word)
	if _, exists := k.keywordMap[upperWord]; exists {
		return fmt.Errorf("keyword '%s' already exists", keyword.Word)
	}
	k.keywordMap[upperWord] = keyword
	if keyword.Reserved {
		k.reservedKeywords[upperWord] = true
	}
	log.Printf("Added keyword: %s", keyword.Word)
	return nil
}
