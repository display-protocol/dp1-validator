package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/display-protocol/dp1-cli/internal/config"
	"github.com/display-protocol/dp1-cli/internal/output"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect or edit ~/.dp1/config.yaml",
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print absolute path of the CLI config file",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := config.Path()
		if err != nil {
			output.PrintError(jsonOut, output.ErrorReport{Command: "config path", Error: err.Error()})
			return errPrinted
		}
		if jsonOut {
			fmt.Fprintf(cmd.OutOrStdout(), `{"path":%q}`+"\n", p)
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), p)
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print ~/.dp1/config.yaml (defaults merged for missing entries)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			output.PrintError(jsonOut, output.ErrorReport{Command: "config show", Error: err.Error()})
			return errPrinted
		}
		if jsonOut {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(output.ConfigShowOK{
				OK:       true,
				Signing:  cfg.Signing,
				Feed:     cfg.Feed,
				Defaults: cfg.Defaults,
			})
		}
		raw, err := yaml.Marshal(cfg)
		if err != nil {
			output.PrintError(jsonOut, output.ErrorReport{Command: "config show", Error: err.Error()})
			return errPrinted
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s", raw)
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			fmt.Fprintln(cmd.OutOrStdout())
		}
		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   `set KEY VALUE`,
	Short: `Set KEY in ~/.dp1/config.yaml; VALUE may be "-" to read stdin (trimmed, first line only)`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			output.PrintError(jsonOut, output.ErrorReport{Command: "config set", Error: err.Error()})
			return errPrinted
		}
		key := strings.TrimSpace(args[0])
		val := args[1]
		if val == "-" {
			b, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				output.PrintError(jsonOut, output.ErrorReport{Command: "config set", Error: err.Error()})
				return errPrinted
			}
			val = trimConfigStdin(b)
		}
		if err := applyConfigMutation(&cfg, key, val); err != nil {
			output.PrintError(jsonOut, output.ErrorReport{Command: "config set", Error: err.Error()})
			return errPrinted
		}
		if err := config.Save(cfg); err != nil {
			output.PrintError(jsonOut, output.ErrorReport{Command: "config set", Error: err.Error()})
			return errPrinted
		}
		if jsonOut {
			fmt.Fprintf(cmd.OutOrStdout(), `{"ok":true,"key":%q}`+"\n", key)
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "saved %s\n", key)
		return nil
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get KEY",
	Short: "Print VALUE for KEY (newline-terminated)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			output.PrintError(jsonOut, output.ErrorReport{Command: "config get", Error: err.Error()})
			return errPrinted
		}
		key := strings.TrimSpace(args[0])
		val, ok := peekConfig(cfg, key)
		if !ok {
			output.PrintError(jsonOut, output.ErrorReport{Command: "config get", Error: "unknown config key"})
			return errPrinted
		}
		if jsonOut {
			fmt.Fprintf(cmd.OutOrStdout(), `{"ok":true,"value":%q}`+"\n", val)
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), val)
		return nil
	},
}

func init() {
	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
}

func trimConfigStdin(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimRight(s[:i], "\r")
	}
	return s
}

func applyConfigMutation(cfg *config.Config, key string, val string) error {
	switch key {
	case "signing.private_key":
		cfg.Signing.PrivateKey = strings.TrimSpace(val)
	case "signing.public_key":
		cfg.Signing.PublicKey = strings.TrimSpace(val)
	case "feed.url":
		cfg.Feed.URL = strings.TrimSpace(val)
	case "defaults.output_format":
		v := strings.TrimSpace(val)
		if v != "human" && v != "json" {
			return fmt.Errorf(`defaults.output_format must be "human" or "json"`)
		}
		cfg.Defaults.OutputFormat = v
	default:
		return fmt.Errorf(`unknown key %q (supported: signing.private_key, signing.public_key, feed.url, defaults.output_format)`, key)
	}
	return nil
}

func peekConfig(cfg config.Config, key string) (string, bool) {
	switch key {
	case "signing.private_key":
		return cfg.Signing.PrivateKey, true
	case "signing.public_key":
		return cfg.Signing.PublicKey, true
	case "feed.url":
		return cfg.Feed.URL, true
	case "defaults.output_format":
		return cfg.Defaults.OutputFormat, true
	default:
		return "", false
	}
}
