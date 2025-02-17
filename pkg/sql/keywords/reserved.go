package keywords

import "strings"

func (k *Keywords) GetKeyword(word string) (Keyword, bool) {
	keyword, ok := k.keywordMap[strings.ToUpper(word)]
	return keyword, ok
}
