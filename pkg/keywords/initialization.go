package keywords

import (
	"fmt"
)

// NewKeywords creates a new Keywords instance with the default SQL keywords
func NewKeywords() (*Keywords, error) {
	k := &Keywords{
		reservedKeywords: make(map[string]bool),
		keywordMap:       make(map[string]Keyword),
	}
	if err := k.initializeKeywords(); err != nil {
		return nil, err
	}
	return k, nil
}

// Initialize all keywords
func (k *Keywords) initializeKeywords() error {
	// Initialize all keyword categories
	categories := []struct {
		keywords []Keyword
		category keywordCategory
	}{
		{k.getDMLKeywords(), categoryDML},
		{k.getJoinKeywords(), categoryJoin},
		{k.getOperatorKeywords(), categoryOperator},
		{k.getStorageKeywords(), categoryStorage},
		{k.getConstraintKeywords(), categoryConstraint},
		{k.getTransactionKeywords(), categoryTxn},
		{k.getJSONKeywords(), categoryJson},
		{k.getSecurityKeywords(), categoryAuth},
		{k.getFlowControlKeywords(), categoryFlow},
		{k.getHAKeywords(), categoryHA},
		{k.getSchemaKeywords(), categorySchema},
		{k.getReplicationKeywords(), categoryHA},
	}

	// Add keywords from each category
	for _, cat := range categories {
		if err := k.addKeywords(cat.keywords, cat.category); err != nil {
			return err
		}
	}

	return nil
}

// Helper method to add keywords to the keyword map
func (k *Keywords) addKeywords(keywords []Keyword, category keywordCategory) error {
	for _, keyword := range keywords {
		if err := k.addKeyword(keyword, category); err != nil {
			return err
		}
	}
	return nil
}

// Helper method to add a single keyword
func (k *Keywords) addKeyword(keyword Keyword, category keywordCategory) error {
	if _, exists := k.keywordMap[keyword.Word]; exists {
		return fmt.Errorf("duplicate keyword: %s", keyword.Word)
	}
	k.keywordMap[keyword.Word] = keyword
	if keyword.Reserved {
		k.reservedKeywords[keyword.Word] = true
	}
	return nil
}
