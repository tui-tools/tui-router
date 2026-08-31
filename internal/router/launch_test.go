package router

import "testing"

// The handoff runs another program, so the one thing that must hold for any
// input is that only a family binary name ever reaches exec. A name that is
// not tui-<word> is refused before a path is ever looked up.
func TestLaunchRefusesANonFamilyName(t *testing.T) {
	for _, name := range []string{
		"", "rm", "sh", "tui-", "tui-firewall; rm -rf /", "../evil",
		"tui-firewall extra", "TUI-FIREWALL", "nottui-firewall",
	} {
		if _, err := launchBinary(name); err == nil {
			t.Errorf("launchBinary(%q) was accepted, want a refusal", name)
		}
		if available(name) {
			t.Errorf("available(%q) = true, want false for a non-family name", name)
		}
	}
}

// A well-formed family name that is simply not installed fails with "not
// installed", never a partial command.
func TestLaunchAbsentToolIsNotInstalled(t *testing.T) {
	// A name that is valid but will not be on any test machine's PATH.
	if _, err := launchBinary("tui-doesnotexist"); err == nil {
		t.Error("expected an error for a tool that is not installed")
	}
}
