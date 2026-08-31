package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-router/internal/router"
)

// checkTimeout bounds the single read --check performs.
const checkTimeout = 30 * time.Second

// checkCard is one card in the --check JSON: the numbers a card rests on and
// whether the tool that manages it is present, so a machine-readable consumer
// gets the same summary the screen shows without the styling.
type checkCard struct {
	Kind      router.CardKind `json:"kind"`
	Title     string          `json:"title"`
	Status    router.Status   `json:"status"`
	Summary   string          `json:"summary"`
	Tool      string          `json:"tool"`
	Installed bool            `json:"toolInstalled"`
}

// checkReport is the whole --check document.
type checkReport struct {
	Tool     string          `json:"tool"`
	Version  string          `json:"version"`
	Backend  string          `json:"backend"`
	Describe string          `json:"describe"`
	Cards    []checkCard     `json:"cards"`
	Snapshot router.Snapshot `json:"snapshot"`
	Compat   []compat.Result `json:"compat"`
}

// runCheck reads every card once and prints the result as JSON. It runs the
// read path only — never a handoff — so it is safe against a production
// router, and its exit code reports whether the tool could read, never a
// verdict about the machine: a router with no firewall is a successful run
// whose bad news travels in the JSON.
func runCheck(backend router.Backend, backends []compat.Result, out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	snap, err := backend.Read(ctx)
	if err != nil {
		return fmt.Errorf("%s backend read failed: %w", backend.Name(), err)
	}

	cards := router.Cards(snap, nil, backend.ToolInstalled)
	rows := make([]checkCard, 0, len(cards))
	for _, card := range cards {
		rows = append(rows, checkCard{
			Kind:      card.Kind,
			Title:     card.Title,
			Status:    card.Status,
			Summary:   card.Summary,
			Tool:      card.Tool,
			Installed: card.ToolInstalled,
		})
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(checkReport{
		Tool:     toolName,
		Version:  version,
		Backend:  backend.Name(),
		Describe: backend.Describe(),
		Cards:    rows,
		Snapshot: snap,
		Compat:   backends,
	})
}
