package config

import (
	"fmt"
	"strings"
)

// ValidDialects lists all supported SQL dialects
var ValidDialects = []string{
	"postgresql",
	"mysql",
	"sqlserver",
	"oracle",
	"sqlite",
	"generic",
}

// ValidOutputFormats lists all supported output formats
var ValidOutputFormats = []string{
	"json",
	"yaml",
	"table",
	"tree",
	"auto",
}

// ConfigSchema defines the structure and constraints for configuration
type ConfigSchema struct {
	Format     FormatSchema     `yaml:"format"`
	Validation ValidationSchema `yaml:"validate"`
	Output     OutputSchema     `yaml:"output"`
	Analyze    AnalyzeSchema    `yaml:"analyze"`
}

// FormatSchema defines constraints for format settings
type FormatSchema struct {
	Indent struct {
		Min     int    `yaml:"min"`
		Max     int    `yaml:"max"`
		Default int    `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"indent"`
	UppercaseKeywords struct {
		Default bool   `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"uppercase_keywords"`
	MaxLineLength struct {
		Min     int    `yaml:"min"`
		Max     int    `yaml:"max"`
		Default int    `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"max_line_length"`
	Compact struct {
		Default bool   `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"compact"`
}

// ValidationSchema defines constraints for validation settings
type ValidationSchema struct {
	Dialect struct {
		Options []string `yaml:"options"`
		Default string   `yaml:"default"`
		Desc    string   `yaml:"description"`
	} `yaml:"dialect"`
	StrictMode struct {
		Default bool   `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"strict_mode"`
	Recursive struct {
		Default bool   `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"recursive"`
	Pattern struct {
		Default string `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"pattern"`
}

// OutputSchema defines constraints for output settings
type OutputSchema struct {
	Format struct {
		Options []string `yaml:"options"`
		Default string   `yaml:"default"`
		Desc    string   `yaml:"description"`
	} `yaml:"format"`
	Verbose struct {
		Default bool   `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"verbose"`
}

// AnalyzeSchema defines constraints for analyze settings
type AnalyzeSchema struct {
	Security struct {
		Default bool   `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"security"`
	Performance struct {
		Default bool   `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"performance"`
	Complexity struct {
		Default bool   `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"complexity"`
	All struct {
		Default bool   `yaml:"default"`
		Desc    string `yaml:"description"`
	} `yaml:"all"`
}

// GetSchema returns the complete configuration schema with descriptions
func GetSchema() *ConfigSchema {
	return &ConfigSchema{
		Format: FormatSchema{
			Indent: struct {
				Min     int    `yaml:"min"`
				Max     int    `yaml:"max"`
				Default int    `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Min:     0,
				Max:     8,
				Default: 2,
				Desc:    "Number of spaces for indentation (0-8)",
			},
			UppercaseKeywords: struct {
				Default bool   `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: true,
				Desc:    "Convert SQL keywords to uppercase",
			},
			MaxLineLength: struct {
				Min     int    `yaml:"min"`
				Max     int    `yaml:"max"`
				Default int    `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Min:     0,
				Max:     500,
				Default: 80,
				Desc:    "Maximum line length for formatting (0-500, 0 = unlimited)",
			},
			Compact: struct {
				Default bool   `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: false,
				Desc:    "Use compact formatting with minimal whitespace",
			},
		},
		Validation: ValidationSchema{
			Dialect: struct {
				Options []string `yaml:"options"`
				Default string   `yaml:"default"`
				Desc    string   `yaml:"description"`
			}{
				Options: ValidDialects,
				Default: "postgresql",
				Desc:    "SQL dialect for validation",
			},
			StrictMode: struct {
				Default bool   `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: false,
				Desc:    "Enable strict validation mode",
			},
			Recursive: struct {
				Default bool   `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: false,
				Desc:    "Recursively process directories",
			},
			Pattern: struct {
				Default string `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: "*.sql",
				Desc:    "File pattern for recursive processing",
			},
		},
		Output: OutputSchema{
			Format: struct {
				Options []string `yaml:"options"`
				Default string   `yaml:"default"`
				Desc    string   `yaml:"description"`
			}{
				Options: ValidOutputFormats,
				Default: "auto",
				Desc:    "Output format for analysis results",
			},
			Verbose: struct {
				Default bool   `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: false,
				Desc:    "Enable verbose output",
			},
		},
		Analyze: AnalyzeSchema{
			Security: struct {
				Default bool   `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: true,
				Desc:    "Enable security analysis",
			},
			Performance: struct {
				Default bool   `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: true,
				Desc:    "Enable performance analysis",
			},
			Complexity: struct {
				Default bool   `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: true,
				Desc:    "Enable complexity analysis",
			},
			All: struct {
				Default bool   `yaml:"default"`
				Desc    string `yaml:"description"`
			}{
				Default: false,
				Desc:    "Enable all analysis features",
			},
		},
	}
}

// ValidateDialect checks if a dialect is valid
func ValidateDialect(dialect string) error {
	for _, valid := range ValidDialects {
		if dialect == valid {
			return nil
		}
	}
	return fmt.Errorf("invalid dialect '%s', must be one of: %s", dialect, strings.Join(ValidDialects, ", "))
}

// ValidateOutputFormat checks if an output format is valid
func ValidateOutputFormat(format string) error {
	for _, valid := range ValidOutputFormats {
		if format == valid {
			return nil
		}
	}
	return fmt.Errorf("invalid output format '%s', must be one of: %s", format, strings.Join(ValidOutputFormats, ", "))
}

// ValidateIndent checks if indent value is within acceptable range
func ValidateIndent(indent int) error {
	if indent < 0 || indent > 8 {
		return fmt.Errorf("indent must be between 0 and 8, got %d", indent)
	}
	return nil
}

// ValidateMaxLineLength checks if max line length is within acceptable range
func ValidateMaxLineLength(length int) error {
	if length < 0 || length > 500 {
		return fmt.Errorf("max_line_length must be between 0 and 500, got %d", length)
	}
	return nil
}
