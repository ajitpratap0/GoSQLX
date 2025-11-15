package cmd

import (
	_ "embed"
	"os"

	"github.com/spf13/cobra"
)

//go:embed config_template.yml
var configTemplate string

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
	// Create options from flags
	flags := ConfigManagerFlags{
		Force:   false, // Force flag not implemented yet
		Verbose: verbose,
	}
	opts := ConfigManagerOptionsFromFlags(flags)

	// Create config manager with injectable output
	cm := NewConfigManager(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, configTemplate)

	// Run init
	_, err := cm.Init(configPath)
	return err
}

func configValidateRun(cmd *cobra.Command, args []string) error {
	// Create options from flags
	flags := ConfigManagerFlags{
		Verbose: verbose,
	}
	opts := ConfigManagerOptionsFromFlags(flags)

	// Create config manager with injectable output
	cm := NewConfigManager(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, configTemplate)

	// Run validation
	result, err := cm.Validate(configFile)
	if err != nil {
		// Exit with error code if validation failed
		if result != nil && !result.Valid {
			os.Exit(1)
		}
		return err
	}

	return nil
}

func configShowRun(cmd *cobra.Command, args []string) error {
	// Create options from flags
	flags := ConfigManagerFlags{
		Format:  format,
		Verbose: verbose,
	}
	opts := ConfigManagerOptionsFromFlags(flags)

	// Create config manager with injectable output
	cm := NewConfigManager(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, configTemplate)

	// Run show
	_, err := cm.Show(configFile)
	return err
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
