package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tui-tools/tui-router/internal/router"
)

// TestRunCheckDemo asserts the shape --check promises: one row per card with
// the summary and which managing tool is present, plus the compat block, and a
// successful run even though every managing tool is absent — a machine's state
// is never a check failure.
func TestRunCheckDemo(t *testing.T) {
	var out strings.Builder
	backend := router.NewFake()
	if err := runCheck(backend, nil, &out); err != nil {
		t.Fatalf("runCheck: %v", err)
	}

	var report struct {
		Tool    string `json:"tool"`
		Backend string `json:"backend"`
		Cards   []struct {
			Kind      string `json:"kind"`
			Summary   string `json:"summary"`
			Tool      string `json:"tool"`
			Installed bool   `json:"toolInstalled"`
		} `json:"cards"`
		Snapshot router.Snapshot `json:"snapshot"`
	}
	if err := json.Unmarshal([]byte(out.String()), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}

	if report.Tool != toolName || report.Backend != "demo" {
		t.Errorf("tool/backend = %q/%q", report.Tool, report.Backend)
	}
	if len(report.Cards) != len(router.Kinds) {
		t.Fatalf("got %d cards, want %d", len(report.Cards), len(router.Kinds))
	}
	for _, card := range report.Cards {
		if card.Summary == "" || card.Tool == "" {
			t.Errorf("card %q has no summary or tool: %+v", card.Kind, card)
		}
		if card.Installed {
			t.Errorf("demo should report every managing tool absent: %+v", card)
		}
	}
	// The snapshot travels with the check, so a consumer has the numbers, not
	// only the verdicts.
	if len(report.Snapshot.Interfaces) == 0 {
		t.Error("check should carry the snapshot's interfaces")
	}
}
