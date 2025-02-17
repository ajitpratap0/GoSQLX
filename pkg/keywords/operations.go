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

func (k *Keywords) IsKeyword(word string) bool {
	_, ok := k.keywordMap[strings.ToUpper(word)]
	return ok
}
