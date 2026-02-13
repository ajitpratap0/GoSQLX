package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// FormatterConfig holds all formatting preferences
type FormatterConfig struct {
	// Keyword casing: "upper", "lower", "title"
	KeywordCase string `json:"keyword_case"`

	// Indentation: number of spaces (use 0 for tabs)
	IndentSpaces int `json:"indent_spaces"`

	// Maximum line length before wrapping
	MaxLineLength int `json:"max_line_length"`

	// Comma style: "leading", "trailing"
	CommaStyle string `json:"comma_style"`

	// Add spaces around operators (=, +, -, etc.)
	SpaceAroundOperators bool `json:"space_around_operators"`

	// Align JOIN keywords
	AlignJoins bool `json:"align_joins"`

	// Uppercase function names
	UppercaseFunctions bool `json:"uppercase_functions"`
}

// DefaultConfig returns the default formatting configuration
func DefaultConfig() FormatterConfig {
	return FormatterConfig{
		KeywordCase:          "upper",
		IndentSpaces:         4,
		MaxLineLength:        80,
		CommaStyle:           "leading",
		SpaceAroundOperators: true,
		AlignJoins:           true,
		UppercaseFunctions:   true,
	}
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(filePath string) (FormatterConfig, error) {
	// If file doesn't exist, return default config
	if _, err := os.Stat(filePath); os.IsNotExist(err) { // #nosec G703
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(filepath.Clean(filePath)) // #nosec G304 // #nosec G304,G703
	if err != nil {
		return FormatterConfig{}, err
	}

	var config FormatterConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return FormatterConfig{}, err
	}

	return config, nil
}

// SaveConfig saves configuration to a JSON file
func SaveConfig(config FormatterConfig, filePath string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0600)
}
