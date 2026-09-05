package cmd_test

import (
	"strings"
	"testing"

	"github.com/display-protocol/dp1-cli/cmd"
)

func TestPlaylist_validateRequiresOneSourceArg(t *testing.T) {
	assertExecuteFails(t, []string{"playlist", "validate"})
	assertExecuteFails(t, []string{"playlist", "validate", "a", "b"})
}

func TestPlaylist_verifyRequiresOneSourceArg(t *testing.T) {
	assertExecuteFails(t, []string{"playlist", "verify"})
	assertExecuteFails(t, []string{"playlist", "verify", "a", "b"})
}

func TestPlaylist_validateAndVerify_useDocumentsSourceArg(t *testing.T) {
	for _, leaf := range []string{"validate", "verify"} {
		c := mustFindCmd(t, cmd.Root, "playlist", leaf)
		if !strings.Contains(c.Use, "<source>") {
			t.Fatalf("playlist %s: Use line should document <source>: %q", leaf, c.Use)
		}
	}
}

func TestPlaylist_verify_hasOptionalPubkeyFlag(t *testing.T) {
	c := mustFindCmd(t, cmd.Root, "playlist", "verify")
	if c.Args == nil {
		t.Fatal("expected Args validator on playlist verify")
	}
	fl := c.LocalFlags().Lookup("pubkey")
	if fl == nil {
		t.Fatal(`expected local --pubkey on playlist verify`)
	}
	if fl.DefValue != "" {
		t.Fatalf("pubkey default should be empty, got %q", fl.DefValue)
	}
	if !strings.Contains(fl.Usage, "did:key") {
		t.Fatalf("pubkey usage should mention did:key: %q", fl.Usage)
	}
}

func TestPlaylist_validate_hasNoPubkeyFlag(t *testing.T) {
	c := mustFindCmd(t, cmd.Root, "playlist", "validate")
	if c.LocalFlags().Lookup("pubkey") != nil {
		t.Fatal("playlist validate should not define local --pubkey")
	}
}

func TestPlaylist_validate_hasAllowUnsignedFlag(t *testing.T) {
	c := mustFindCmd(t, cmd.Root, "playlist", "validate")
	fl := c.Flags().Lookup("allow-unsigned")
	if fl == nil {
		t.Fatal("expected --allow-unsigned on playlist validate")
	}
	if fl.DefValue != "false" {
		t.Fatalf("allow-unsigned default should be false, got %q", fl.DefValue)
	}
}

func TestPlaylist_createAndSign_registered(t *testing.T) {
	_ = mustFindCmd(t, cmd.Root, "playlist", "create")
	s := mustFindCmd(t, cmd.Root, "playlist", "sign")
	if s.Flag("role") == nil || s.Flag("private-key") == nil {
		t.Fatal("expected sign flags role and private-key")
	}
}

func TestPlaylist_publishRequiresOneSourceArg(t *testing.T) {
	assertExecuteFails(t, []string{"playlist", "publish"})
	assertExecuteFails(t, []string{"playlist", "publish", "a", "b"})
}

func TestPlaylist_publish_registersWithFlags(t *testing.T) {
	c := mustFindCmd(t, cmd.Root, "playlist", "publish")
	if c.Args == nil {
		t.Fatal("expected Args validator on playlist publish")
	}
	if !strings.Contains(c.Use, "<source>") {
		t.Fatalf("should document <source>: %q", c.Use)
	}
	fl := c.Flags()
	if fl.Lookup("feed-url") == nil {
		t.Fatal("expected feed-url flag")
	}
}
