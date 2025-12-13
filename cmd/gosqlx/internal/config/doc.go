// Package config provides configuration file management for the gosqlx CLI.
//
// # Overview
//
// This package handles loading, parsing, validating, and saving configuration files
// for the gosqlx CLI. Configuration files allow users to set default values for
// command options, reducing the need for repetitive command-line flags.
//
// # Configuration File Format
//
// GoSQLX uses YAML format for configuration files (.gosqlx.yml):
//
//	format:
//	  indent: 2
//	  uppercase_keywords: true
//	  max_line_length: 80
//	  compact: false
//
//	validate:
//	  dialect: postgresql
//	  strict_mode: false
//	  recursive: false
//	  pattern: "*.sql"
//	  security:
//	    max_file_size: 10485760  # 10MB
//
//	output:
//	  format: auto
//	  verbose: false
//
//	analyze:
//	  security: true
//	  performance: true
//	  complexity: true
//	  all: false
//
// # Configuration Search Path
//
// Configuration files are searched in the following order with precedence:
//
//  1. Current directory: .gosqlx.yml
//  2. Home directory: ~/.gosqlx.yml
//  3. System-wide: /etc/gosqlx.yml
//  4. Built-in defaults (if no config file found)
//
// CLI flags always override configuration file settings.
//
// # Usage
//
// ## Loading Configuration
//
// Load from default locations:
//
//	cfg, err := config.LoadDefault()
//	if err != nil {
//	    // Handle error or use defaults
//	    cfg = config.DefaultConfig()
//	}
//
// Load from specific file:
//
//	cfg, err := config.Load("/path/to/config.yml")
//	if err != nil {
//	    return err
//	}
//
// ## Creating Configuration
//
// Create with defaults:
//
//	cfg := config.DefaultConfig()
//
// Customize settings:
//
//	cfg.Format.Indent = 4
//	cfg.Format.UppercaseKeywords = false
//	cfg.Validation.Dialect = "mysql"
//
// ## Saving Configuration
//
// Save to file:
//
//	if err := cfg.Save(".gosqlx.yml"); err != nil {
//	    return err
//	}
//
// ## Validation
//
// Configuration is automatically validated during Load():
//
//	cfg, err := config.Load("config.yml")
//	// cfg is validated, or err contains validation errors
//
// Explicit validation:
//
//	if err := cfg.Validate(); err != nil {
//	    // Handle validation errors
//	}
//
// ## Merging Configurations
//
// Merge CLI flags with config file (CLI flags take precedence):
//
//	cfg, _ := config.LoadDefault()
//	cliConfig := &config.Config{
//	    Format: config.FormatConfig{Indent: 4}, // From CLI flag
//	}
//	cfg.Merge(cliConfig)
//
// # Configuration Sections
//
// ## Format Configuration
//
// Controls SQL formatting behavior:
//
//	format:
//	  indent: 2                    # Indentation size in spaces (0-8)
//	  uppercase_keywords: true     # Uppercase SQL keywords
//	  max_line_length: 80          # Maximum line length (0-500)
//	  compact: false               # Compact format (minimal whitespace)
//
// Fields:
//   - Indent: Number of spaces for indentation (default: 2)
//   - UppercaseKeywords: Convert keywords to uppercase (default: true)
//   - MaxLineLength: Maximum line length for wrapping (default: 80)
//   - Compact: Use compact format with minimal whitespace (default: false)
//
// ## Validation Configuration
//
// Controls SQL validation behavior:
//
//	validate:
//	  dialect: postgresql          # SQL dialect for validation
//	  strict_mode: false           # Enable strict validation
//	  recursive: false             # Recursively process directories
//	  pattern: "*.sql"             # File pattern for recursive processing
//	  security:
//	    max_file_size: 10485760    # Maximum file size in bytes
//
// Fields:
//   - Dialect: SQL dialect (postgresql, mysql, sqlserver, oracle, sqlite, generic)
//   - StrictMode: Enable strict validation rules (default: false)
//   - Recursive: Recursively process directories (default: false)
//   - Pattern: File pattern for recursive processing (default: "*.sql")
//   - Security.MaxFileSize: Maximum allowed file size in bytes (default: 10MB)
//
// ## Output Configuration
//
// Controls output formatting and verbosity:
//
//	output:
//	  format: auto                 # Output format (json, yaml, table, tree, auto)
//	  verbose: false               # Enable verbose output
//
// Fields:
//   - Format: Output format (json, yaml, table, tree, auto) (default: auto)
//   - Verbose: Enable detailed output for debugging (default: false)
//
// ## Analysis Configuration
//
// Controls SQL analysis behavior:
//
//	analyze:
//	  security: true               # Perform security analysis
//	  performance: true            # Perform performance analysis
//	  complexity: true             # Calculate complexity metrics
//	  all: false                   # Comprehensive analysis (all above)
//
// Fields:
//   - Security: Enable security vulnerability detection (default: true)
//   - Performance: Enable performance analysis (default: true)
//   - Complexity: Enable complexity metrics (default: true)
//   - All: Enable comprehensive analysis (default: false)
//
// # Configuration Validation
//
// The package validates configuration values to ensure they are within acceptable ranges:
//
// Format validation:
//   - Indent: 0-8 spaces
//   - MaxLineLength: 0-500 characters
//
// Validation validation:
//   - Dialect: Must be one of: postgresql, mysql, sqlserver, oracle, sqlite, generic
//
// Output validation:
//   - Format: Must be one of: json, yaml, table, tree, auto
//
// Invalid configurations are rejected with descriptive error messages.
//
// # CLI Flag Precedence
//
// Configuration files provide defaults, but CLI flags always take precedence:
//
//	# Config file has indent: 2
//	gosqlx format query.sql               # Uses indent: 2 from config
//	gosqlx format --indent 4 query.sql    # Uses indent: 4 from CLI flag
//
// The package tracks which flags were explicitly set to ensure proper precedence.
//
// # Schema Validation
//
// The package provides schema validation utilities in schema.go:
//
//   - Schema definition for configuration structure
//   - Type checking for configuration values
//   - Range validation for numeric values
//   - Enum validation for string values
//
// Schema validation is used by:
//   - Load() function to validate loaded configurations
//   - Validate() method to check configuration correctness
//   - CLI config validate command to verify user configurations
//
// # Error Handling
//
// Configuration errors are returned with context:
//
//	cfg, err := config.Load("config.yml")
//	if err != nil {
//	    // Possible errors:
//	    // - File not found
//	    // - YAML parsing error
//	    // - Validation error
//	    // - Home directory lookup failure
//	}
//
// Validation errors include field names and acceptable ranges:
//
//	invalid configuration: format.indent must be between 0 and 8, got 10
//	invalid configuration: validate.dialect must be one of: [postgresql mysql ...], got 'custom'
//
// # Best Practices
//
// ## Project Configuration
//
// Place .gosqlx.yml in project root for team-wide defaults:
//
//	# .gosqlx.yml
//	format:
//	  indent: 2
//	  uppercase_keywords: true
//
//	validate:
//	  dialect: postgresql
//	  recursive: true
//
// ## User Configuration
//
// Place .gosqlx.yml in home directory for personal defaults:
//
//	# ~/.gosqlx.yml
//	output:
//	  verbose: true
//
//	format:
//	  indent: 4
//
// ## CI/CD Configuration
//
// Use explicit flags in CI/CD for clarity and reproducibility:
//
//	gosqlx validate --dialect postgresql --strict ./sql/
//	gosqlx format --check --indent 2 ./sql/*.sql
//
// # Thread Safety
//
// Configuration objects are not thread-safe. Each goroutine should have its own
// configuration instance or use appropriate synchronization.
//
// Loading configuration is safe for concurrent use as it creates new instances.
//
// # Performance
//
// Configuration loading is optimized:
//   - Files are loaded once and cached by the application
//   - YAML parsing uses efficient unmarshalers
//   - Validation is performed once at load time
//
// Configuration file size should be kept small (< 1KB typically) for fast loading.
//
// # Examples
//
// ## Complete Configuration Example
//
//	# .gosqlx.yml - Complete configuration example
//	format:
//	  indent: 2
//	  uppercase_keywords: true
//	  max_line_length: 80
//	  compact: false
//
//	validate:
//	  dialect: postgresql
//	  strict_mode: false
//	  recursive: true
//	  pattern: "*.sql"
//	  security:
//	    max_file_size: 10485760
//
//	output:
//	  format: auto
//	  verbose: false
//
//	analyze:
//	  security: true
//	  performance: true
//	  complexity: true
//	  all: false
//
// ## Programmatic Configuration
//
//	// Create custom configuration
//	cfg := &config.Config{
//	    Format: config.FormatConfig{
//	        Indent:            4,
//	        UppercaseKeywords: false,
//	        MaxLineLength:     120,
//	        Compact:           false,
//	    },
//	    Validation: config.ValidationConfig{
//	        Dialect:    "mysql",
//	        StrictMode: true,
//	        Recursive:  true,
//	        Pattern:    "*.sql",
//	        Security: config.SecurityConfig{
//	            MaxFileSize: 5 * 1024 * 1024, // 5MB
//	        },
//	    },
//	    Output: config.OutputConfig{
//	        Format:  "json",
//	        Verbose: true,
//	    },
//	    Analyze: config.AnalyzeConfig{
//	        Security:    true,
//	        Performance: true,
//	        Complexity:  true,
//	        All:         false,
//	    },
//	}
//
//	// Validate
//	if err := cfg.Validate(); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Save to file
//	if err := cfg.Save(".gosqlx.yml"); err != nil {
//	    log.Fatal(err)
//	}
//
// # See Also
//
//   - cmd/gosqlx/cmd/config.go - Config management commands
//   - cmd/gosqlx/cmd/config_manager.go - Config manager implementation
//   - docs/CONFIGURATION.md - User-facing configuration documentation
package config
