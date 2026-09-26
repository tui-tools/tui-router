package router

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture is `tui-tailscale --demo --check` verbatim: a node that is
// online with two peers, on a host that also runs headscale with three nodes
// and one step short of ready (the unit does not start at boot).
func TestParseTailscaleCheckDemoFixture(t *testing.T) {
	got := ParseTailscaleCheck(fixture(t, "tui-tailscale-check.json"))
	want := Tailnet{
		Available: true, Client: true, Daemon: true, State: "Running",
		Online: true, Peers: 2, PeersOnline: 2,
		ControlPlane: true, Nodes: 3, NodesOnline: 3, Next: "unit",
	}
	if got.NextStep == "" {
		t.Error("the readiness step in words was not read")
	}
	got.NextStep = ""
	if got != want {
		t.Errorf("ParseTailscaleCheck = %+v\nwant %+v", got, want)
	}

	card := tailnetCard(Snapshot{Tailnet: ParseTailscaleCheck(fixture(t, "tui-tailscale-check.json"))})
	if card.Summary != "node online · headscale: unit" {
		t.Errorf("summary = %q", card.Summary)
	}
	if card.Status != StatusWarn {
		t.Errorf("a control plane that is not ready should warn, got %q", card.Status)
	}
	joined := strings.Join(card.Lines, "\n")
	for _, want := range []string{"2 of 2 online", "control: 3 of 3 nodes online", "won't start at boot"} {
		if !strings.Contains(joined, want) {
			t.Errorf("lines %q lack %q", card.Lines, want)
		}
	}
}

// A document of the wrong shape never becomes a state: it is refused with a
// reason the card shows as unknown.
func TestParseTailscaleCheckRefusesBadInput(t *testing.T) {
	for name, text := range map[string]string{
		"not json":       "tailscale is not running",
		"another tool":   `{"tool":"tui-update","tailscale":{},"headscale":{}}`,
		"no halves":      `{"tool":"tui-tailscale"}`,
		"no headscale":   `{"tool":"tui-tailscale","tailscale":{"installed":true}}`,
		"negative count": `{"tool":"tui-tailscale","tailscale":{"peers":{"total":-1}},"headscale":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := ParseTailscaleCheck(text)
			if got.Available || got.Reason == "" {
				t.Errorf("ParseTailscaleCheck(%q) = %+v, want not available with a reason", text, got)
			}
			if card := tailnetCard(Snapshot{Tailnet: got}); card.Status != StatusUnknown {
				t.Errorf("card status = %q, want unknown", card.Status)
			}
		})
	}
}

// The card's headline for the states a host can be in.
func TestTailnetCardStates(t *testing.T) {
	cases := []struct {
		name    string
		tailnet Tailnet
		status  Status
		summary string
	}{
		{"node only, online",
			Tailnet{Available: true, Client: true, Daemon: true, State: "Running", Online: true, Peers: 4, PeersOnline: 3},
			StatusOK, "node online · 3 of 4 peers"},
		{"node waiting for a login",
			Tailnet{Available: true, Client: true, Daemon: true, State: "NeedsLogin"},
			StatusWarn, "node NeedsLogin"},
		{"nothing here",
			Tailnet{Available: true},
			StatusInfo, "no tailscale client · no headscale"},
		{"control plane only, ready",
			Tailnet{Available: true, ControlPlane: true, Nodes: 5, NodesOnline: 4, Next: TailnetReady},
			StatusOK, "headscale ready · 5 nodes"},
		{"node and ready control plane",
			Tailnet{Available: true, Client: true, Daemon: true, State: "Running", Online: true,
				ControlPlane: true, Nodes: 2, NodesOnline: 2, Next: TailnetReady},
			StatusOK, "node online · headscale ready"},
		{"node stopped beside a ready control plane",
			Tailnet{Available: true, Client: true, ControlPlane: true, Next: TailnetReady},
			StatusWarn, "node stopped · headscale ready"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			card := tailnetCard(Snapshot{Tailnet: tc.tailnet})
			if card.Status != tc.status || card.Summary != tc.summary {
				t.Errorf("card = (%q, %q), want (%q, %q)", card.Status, card.Summary, tc.status, tc.summary)
			}
		})
	}
}

// Without tui-tailscale the card says so in the words of every other card's
// foot, with the family's install hint, and ENTER has nothing to launch.
func TestTailnetCardNotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	got := probeTailnet(context.Background())
	if got.Available || got.Reason != TailnetNotInstalled {
		t.Fatalf("probeTailnet without the binary = %+v", got)
	}
	cards := Cards(Snapshot{Tailnet: got}, nil, available)
	var card Card
	for _, c := range cards {
		if c.Kind == CardTailnet {
			card = c
		}
	}
	if card.Summary != "tui-tailscale (not installed)" || card.Status != StatusUnknown {
		t.Errorf("card = (%q, %q)", card.Status, card.Summary)
	}
	if len(card.Lines) != 1 || !strings.Contains(card.Lines[0], "pkgs.tui.tools") {
		t.Errorf("card lines = %q, want the install hint", card.Lines)
	}
	if card.Tool != "tui-tailscale" || card.ToolInstalled {
		t.Errorf("card tool = (%q, %v), want tui-tailscale not installed", card.Tool, card.ToolInstalled)
	}
}

// ENTER on the Tailnet card runs tui-tailscale with no argument: the argv is
// the resolved absolute path and nothing else, so it opens its own default
// view the way every other hand-off does.
func TestTailnetCardHandsOffToTuiTailscale(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tui-tailscale")
	// The stand-in must be executable for LookPath to find it.
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // an executable test stub in a temp dir
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	tool, ok, hint := resolveTool(CardTailnet, available)
	if tool != "tui-tailscale" || !ok || hint != "" {
		t.Fatalf("resolveTool = (%q, %v, %q)", tool, ok, hint)
	}
	proc, err := (&Real{}).Launch(tool)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	args := proc.(*process).cmd.Args
	if len(args) != 1 || args[0] != bin {
		t.Errorf("hand-off argv = %q, want [%q]", args, bin)
	}
}

// The demo shows a plausible tailnet: the same state the fixture carries.
func TestDemoTailnetCard(t *testing.T) {
	snap, _ := NewFake().Read(context.Background())
	card := tailnetCard(snap)
	if card.Summary != "node online · headscale: unit" || card.Status != StatusWarn {
		t.Errorf("demo tailnet card = (%q, %q)", card.Status, card.Summary)
	}
}
