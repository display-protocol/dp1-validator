package cmd_test

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"

	"github.com/display-protocol/dp1-cli/cmd"
	"github.com/display-protocol/dp1-cli/internal/config"
)

// captureStdout redirects process stdout for the duration of fn (used when output uses os.Stdout).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

func lookupCmd(root *cobra.Command, path ...string) *cobra.Command {
	cur := root
	for _, name := range path {
		var next *cobra.Command
		for _, c := range cur.Commands() {
			if c.Name() == name {
				next = c
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// resetCLIState clears persistent and sign subcommand flags so integration tests do not leak state.
func resetCLIState(t *testing.T) {
	t.Helper()
	config.InvalidateCache()
	root := cmd.Root
	if err := root.PersistentFlags().Set("json", "false"); err != nil {
		t.Fatal(err)
	}
	for _, path := range [][]string{{"playlist", "validate"}, {"channel", "validate"}, {"group", "validate"}} {
		c := lookupCmd(root, path...)
		if c == nil {
			continue
		}
		_ = c.Flags().Set("allow-unsigned", "false")
	}
	if c := lookupCmd(root, "key", "generate"); c != nil {
		_ = c.Flags().Set("save-config", "false")
	}
	for _, path := range [][]string{{"playlist", "sign"}, {"channel", "sign"}, {"group", "sign"}} {
		c := lookupCmd(root, path...)
		if c == nil {
			continue
		}
		fl := c.Flags()
		for _, name := range []string{"private-key", "output", "ts"} {
			_ = fl.Set(name, "")
		}
		if rfl := fl.Lookup("role"); rfl != nil {
			_ = fl.Set("role", rfl.DefValue)
		}
	}
	for _, path := range [][]string{{"playlist", "verify"}, {"channel", "verify"}, {"group", "verify"}} {
		c := lookupCmd(root, path...)
		if c == nil {
			continue
		}
		_ = c.Flags().Set("pubkey", "")
	}
	for _, path := range [][]string{{"playlist", "publish"}, {"channel", "publish"}, {"group", "publish"}} {
		c := lookupCmd(root, path...)
		if c == nil {
			continue
		}
		fl := c.Flags()
		_ = fl.Set("feed-url", "")
	}
}

func childNames(parent *cobra.Command) []string {
	var out []string
	for _, c := range parent.Commands() {
		out = append(out, c.Name())
	}
	return out
}

func mustFindCmd(t *testing.T, root *cobra.Command, path ...string) *cobra.Command {
	t.Helper()
	cur := root
	for _, name := range path {
		var next *cobra.Command
		for _, c := range cur.Commands() {
			if c.Name() == name {
				next = c
				break
			}
		}
		if next == nil {
			t.Fatalf("missing subcommand %q under %q (have: %v)", name, cur.Name(), childNames(cur))
		}
		cur = next
	}
	return cur
}

func assertExecuteFails(t *testing.T, argv []string) {
	t.Helper()
	resetCLIState(t)
	root := cmd.Root
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	root.SetArgs(argv)
	err := root.Execute()
	if err == nil {
		t.Fatalf("expected error for args %v", argv)
	}
}
