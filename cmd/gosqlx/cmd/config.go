package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ajitpratap0/GoSQLX/cmd/gosqlx/internal/config"
)

var (
	configFile string
	configPath string
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage GoSQLX configuration",
	Long: `Manage GoSQLX configuration files.

The configuration file provides default settings for all CLI commands.
Configuration files are searched in the following order:
  1. Current directory: .gosqlx.yml
  2. Home directory: ~/.gosqlx.yml
  3. System: /etc/gosqlx.yml

CLI flags always override configuration file settings.`,
}

// configInitCmd initializes a new configuration file
var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a default configuration file",
	Long: `Create a default .gosqlx.yml configuration file in the current directory.

Examples:
  gosqlx config init                    # Create .gosqlx.yml in current directory
  gosqlx config init --path ~/.gosqlx.yml  # Create config in home directory`,
	RunE: configInitRun,
}

// configValidateCmd validates the configuration file
var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	Long: `Validate the configuration file for syntax and semantic errors.

Examples:
  gosqlx config validate                    # Validate default config location
  gosqlx config validate --file config.yml  # Validate specific file`,
	RunE: configValidateRun,
}

// configShowCmd displays the current configuration
var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long: `Display the current configuration, including merged settings from all sources.

Examples:
  gosqlx config show                    # Show current configuration
  gosqlx config show --format json      # Show as JSON
  gosqlx config show --format yaml      # Show as YAML (default)`,
	RunE: configShowRun,
}

func configInitRun(cmd *cobra.Command, args []string) error {
	// Determine where to create the config
	path := configPath
	if path == "" {
		path = ".gosqlx.yml"
	}

	// Check if file already exists
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("configuration file already exists at %s (use --force to overwrite)", path)
	}

	// Create default config
	cfg := config.DefaultConfig()

	// Save to file
	if err := cfg.Save(path); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	fmt.Printf("✅ Created configuration file: %s\n", path)
	fmt.Printf("\nYou can now customize this file to set your preferred defaults.\n")
	fmt.Printf("Run 'gosqlx config validate' to check your configuration.\n")

	return nil
}

func configValidateRun(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("failed to load configuration from %s: %w", source, err)
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		fmt.Printf("❌ Configuration validation failed:\n")
		fmt.Printf("   %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Configuration is valid\n")
	if configFile != "" {
		fmt.Printf("   Source: %s\n", configFile)
	} else {
		fmt.Printf("   Source: %s\n", source)
	}

	return nil
}

func configShowRun(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Display configuration based on format
	switch format {
	case "json":
		// Use YAML encoder to convert to map, then encode as JSON
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		// For now, just show YAML format
		fmt.Printf("%s", data)
	case "yaml", "auto", "":
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		fmt.Printf("# GoSQLX Configuration\n")
		fmt.Printf("# Source: %s\n\n", source)
		fmt.Printf("%s", data)
	default:
		return fmt.Errorf("unsupported format: %s (use 'json' or 'yaml')", format)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(configCmd)

	// Add subcommands
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configValidateCmd)
	configCmd.AddCommand(configShowCmd)

	// Flags for init subcommand
	configInitCmd.Flags().StringVar(&configPath, "path", "", "path where to create the config file (default: .gosqlx.yml)")

	// Flags for validate and show subcommands
	configValidateCmd.Flags().StringVar(&configFile, "file", "", "config file to validate (default: auto-detect)")
	configShowCmd.Flags().StringVar(&configFile, "file", "", "config file to show (default: auto-detect)")
}

// LoadConfigWithOverrides loads config from default location and merges with CLI flags
// This function is used by other commands to get the effective configuration
func LoadConfigWithOverrides() (*config.Config, error) {
	// Load default config
	cfg, err := config.LoadDefault()
	if err != nil {
		// If we can't load config, use defaults
		cfg = config.DefaultConfig()
	}

	// CLI flags would override config settings
	// This is handled by individual commands that call this function

	return cfg, nil
}
