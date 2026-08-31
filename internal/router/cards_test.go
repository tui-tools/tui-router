package router

import (
	"context"
	"testing"
	"time"
)

func TestThroughputBetweenSnapshots(t *testing.T) {
	t0 := time.Now()
	prev := &Snapshot{At: t0, Counters: []Counter{
		{Name: "eth0", RxBytes: 1000, TxBytes: 2000},
		{Name: "lo", RxBytes: 5, TxBytes: 5},
	}}
	cur := &Snapshot{At: t0.Add(2 * time.Second), Counters: []Counter{
		{Name: "eth0", RxBytes: 3000, TxBytes: 2000},
		{Name: "lo", RxBytes: 9, TxBytes: 9},
	}}
	rates := Throughputs(prev, cur)
	if len(rates) != 1 {
		t.Fatalf("got %d rates, want 1 (lo is excluded)", len(rates))
	}
	// 2000 bytes over 2 seconds is 1000 B/s received.
	if rates[0].Name != "eth0" || rates[0].RxBps != 1000 || rates[0].TxBps != 0 {
		t.Errorf("eth0 rate = %+v, want 1000 rx / 0 tx", rates[0])
	}
}

func TestThroughputGuardsCounterReset(t *testing.T) {
	t0 := time.Now()
	prev := &Snapshot{At: t0, Counters: []Counter{{Name: "eth0", RxBytes: 9000}}}
	cur := &Snapshot{At: t0.Add(time.Second), Counters: []Counter{{Name: "eth0", RxBytes: 10}}}
	rates := Throughputs(prev, cur)
	if len(rates) != 1 || rates[0].RxBps != 0 {
		t.Errorf("a counter reset should read as 0, got %+v", rates)
	}
}

func TestThroughputNeedsTwoPoints(t *testing.T) {
	cur := &Snapshot{At: time.Now(), Counters: []Counter{{Name: "eth0"}}}
	if got := Throughputs(nil, cur); got != nil {
		t.Errorf("a single reading should yield no rate, got %+v", got)
	}
}

func TestCardsCoverEveryKind(t *testing.T) {
	snap, _ := NewFake().Read(context.Background())
	cards := Cards(snap, nil, func(string) bool { return false })
	if len(cards) != len(Kinds) {
		t.Fatalf("got %d cards, want %d", len(cards), len(Kinds))
	}
	for i, kind := range Kinds {
		card := cards[i]
		if card.Kind != kind {
			t.Errorf("card %d is %q, want %q (order is fixed)", i, card.Kind, kind)
		}
		if card.Title == "" || card.Summary == "" {
			t.Errorf("card %q has no title or summary: %+v", kind, card)
		}
		if card.Tool != CardTool[kind] {
			t.Errorf("card %q names tool %q, want %q", kind, card.Tool, CardTool[kind])
		}
	}
}

func TestCardsReportToolInstalled(t *testing.T) {
	installed := func(binary string) bool { return binary == "tui-firewall" }
	snap, _ := NewFake().Read(context.Background())
	cards := Cards(snap, nil, installed)
	for _, card := range cards {
		want := card.Tool == "tui-firewall"
		if card.ToolInstalled != want {
			t.Errorf("card %q installed = %v, want %v", card.Kind, card.ToolInstalled, want)
		}
	}
}

func TestDemoRendersWithNothingInstalled(t *testing.T) {
	snap, err := NewFake().Read(context.Background())
	if err != nil {
		t.Fatalf("demo read: %v", err)
	}
	// The demo router has a WAN and a LAN, an active firewall, a dnsmasq with
	// leases and a WireGuard interface with peers, so every card has content.
	cards := Cards(snap, nil, func(string) bool { return false })
	byKind := map[CardKind]Card{}
	for _, card := range cards {
		byKind[card.Kind] = card
	}
	if byKind[CardFirewall].Status != StatusOK {
		t.Errorf("demo firewall card = %+v, want ok", byKind[CardFirewall])
	}
	if byKind[CardVPN].Status != StatusOK {
		t.Errorf("demo VPN card = %+v, want ok", byKind[CardVPN])
	}
	for _, card := range cards {
		if card.ToolInstalled {
			t.Errorf("demo should report %q's tool absent", card.Kind)
		}
	}
}
