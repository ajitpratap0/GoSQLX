package keywords

import "strings"

func (k *Keywords) IsReserved(word string) bool {
    return k.reservedKeywords[strings.ToUpper(word)]
}

func (k *Keywords) GetKeyword(word string) (Keyword, bool) {
    keyword, ok := k.keywordMap[strings.ToUpper(word)]
    return keyword, ok
}
