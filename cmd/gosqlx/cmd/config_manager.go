package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
)

// ConfigManagerOptions contains configuration for config management
type ConfigManagerOptions struct {
	Format  string // Output format: json, yaml
	Verbose bool   // Enable verbose output
	Force   bool   // Force overwrite existing files
}

// ConfigManager provides configuration management functionality with injectable output
type ConfigManager struct {
	Out      io.Writer
	Err      io.Writer
	Opts     ConfigManagerOptions
	Template string // Config template content
}

// ConfigInitResult contains the result of config initialization
type ConfigInitResult struct {
	Path    string
	Created bool
	Error   error
}

// ConfigValidateResult contains the result of config validation
type ConfigValidateResult struct {
	Valid  bool
	Source string
	Config *config.Config
	Error  error
}

// ConfigShowResult contains the result of config display
type ConfigShowResult struct {
	Config *config.Config
	Source string
	Output string
	Error  error
}

// NewConfigManager creates a new ConfigManager with the given options
func NewConfigManager(out, err io.Writer, opts ConfigManagerOptions, template string) *ConfigManager {
	return &ConfigManager{
		Out:      out,
		Err:      err,
		Opts:     opts,
		Template: template,
	}
}

// Init creates a new configuration file from template
func (cm *ConfigManager) Init(path string) (*ConfigInitResult, error) {
	result := &ConfigInitResult{
		Path:    path,
		Created: false,
	}

	// Use default path if not specified
	if path == "" {
		path = ".gosqlx.yml"
		result.Path = path
	}

	// Check if file already exists
	if _, err := os.Stat(path); err == nil {
		if !cm.Opts.Force {
			result.Error = fmt.Errorf("configuration file already exists at %s (use --force to overwrite)", path)
			return result, result.Error
		}
		// Force mode: will overwrite
		if cm.Opts.Verbose {
			fmt.Fprintf(cm.Out, "Overwriting existing configuration file at %s\n", path)
		}
	}

	// Write the template file
	// G306: Use 0600 for better security (owner read/write only)
	if err := os.WriteFile(path, []byte(cm.Template), 0600); err != nil {
		result.Error = fmt.Errorf("failed to create config file: %w", err)
		return result, result.Error
	}

	result.Created = true

	// Display success message
	fmt.Fprintf(cm.Out, "✅ Created configuration file: %s\n", path)
	fmt.Fprintf(cm.Out, "\nYou can now customize this file to set your preferred defaults.\n")
	fmt.Fprintf(cm.Out, "Run 'gosqlx config validate' to check your configuration.\n")

	return result, nil
}

// Validate validates a configuration file
func (cm *ConfigManager) Validate(configFile string) (*ConfigValidateResult, error) {
	result := &ConfigValidateResult{
		Valid: false,
	}

	var cfg *config.Config
	var err error
	var source string

	// Load from specified file or default location
	if configFile != "" {
		cfg, err = config.Load(configFile)
		source = configFile
	} else {
		cfg, err = config.LoadDefault()
		source = "default locations"
	}

	if err != nil {
		// Check if this is a validation error (from config.Load calling Validate internally)
		if strings.Contains(err.Error(), "invalid configuration:") {
			result.Error = err
			fmt.Fprintf(cm.Out, "❌ Configuration validation failed:\n")
			fmt.Fprintf(cm.Out, "   %v\n", err)
			return result, result.Error
		}
		result.Error = fmt.Errorf("failed to load configuration from %s: %w", source, err)
		return result, result.Error
	}

	result.Config = cfg
	result.Source = source

	// Validate the configuration (should already be validated by Load, but double-check)
	if err := cfg.Validate(); err != nil {
		result.Error = err
		fmt.Fprintf(cm.Out, "❌ Configuration validation failed:\n")
		fmt.Fprintf(cm.Out, "   %v\n", err)
		return result, result.Error
	}

	result.Valid = true

	// Display success message
	fmt.Fprintf(cm.Out, "✅ Configuration is valid\n")
	if configFile != "" {
		fmt.Fprintf(cm.Out, "   Source: %s\n", configFile)
	} else {
		fmt.Fprintf(cm.Out, "   Source: %s\n", source)
	}

	return result, nil
}

// Show displays the current configuration
func (cm *ConfigManager) Show(configFile string) (*ConfigShowResult, error) {
	result := &ConfigShowResult{}

	var cfg *config.Config
	var err error
	var source string

	// Load from specified file or default location
	if configFile != "" {
		cfg, err = config.Load(configFile)
		source = configFile
	} else {
		cfg, err = config.LoadDefault()
		source = "default configuration"
	}

	if err != nil {
		result.Error = fmt.Errorf("failed to load configuration: %w", err)
		return result, result.Error
	}

	result.Config = cfg
	result.Source = source

	// Display configuration based on format
	var output string
	switch cm.Opts.Format {
	case "json":
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			result.Error = fmt.Errorf("failed to marshal config to JSON: %w", err)
			return result, result.Error
		}
		output = string(data)
	case "yaml", "auto", "":
		data, err := yaml.Marshal(cfg)
		if err != nil {
			result.Error = fmt.Errorf("failed to marshal config to YAML: %w", err)
			return result, result.Error
		}
		output = fmt.Sprintf("# GoSQLX Configuration\n# Source: %s\n\n%s", source, string(data))
	default:
		result.Error = fmt.Errorf("unsupported format: %s (use 'json' or 'yaml')", cm.Opts.Format)
		return result, result.Error
	}

	result.Output = output
	fmt.Fprintf(cm.Out, "%s", output)

	return result, nil
}

// ConfigManagerFlags represents CLI flags for config commands
type ConfigManagerFlags struct {
	Format  string
	Verbose bool
	Force   bool
}

// ConfigManagerOptionsFromFlags creates ConfigManagerOptions from CLI flags
func ConfigManagerOptionsFromFlags(flags ConfigManagerFlags) ConfigManagerOptions {
	// Direct type conversion is possible because both structs have identical fields
	return ConfigManagerOptions(flags)
}
