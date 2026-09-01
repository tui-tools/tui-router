package router

import (
	"fmt"
	"strconv"
)

// Cards turns a snapshot into the five cockpit panels. prev, when non-nil, is
// an earlier snapshot used to derive the traffic throughput; installed reports
// whether each card's managing tool is on the machine. This is the single
// place the model becomes what the screen and --check both render, so the two
// can never disagree.
func Cards(snap Snapshot, prev *Snapshot, installed func(string) bool) []Card {
	if installed == nil {
		installed = func(string) bool { return false }
	}
	cards := make([]Card, 0, len(Kinds))
	for _, kind := range Kinds {
		var card Card
		switch kind {
		case CardInterfaces:
			card = interfacesCard(snap)
		case CardFirewall:
			card = firewallCard(snap)
		case CardTraffic:
			card = trafficCard(snap, prev)
		case CardDHCP:
			card = dhcpCard(snap)
		case CardVPN:
			card = vpnCard(snap)
		case CardUpdates:
			card = updatesCard(snap)
		}
		card.Kind = kind
		card.Tool = CardTool[kind]
		card.ToolInstalled = installed(card.Tool)
		cards = append(cards, card)
	}
	return cards
}

// interfacesCard summarises the interfaces and their WAN/LAN roles.
func interfacesCard(snap Snapshot) Card {
	wan, lan, wanUp := 0, 0, 0
	lines := make([]string, 0, len(snap.Interfaces))
	for _, iface := range snap.Interfaces {
		if iface.Role == "other" && iface.Name == "lo" {
			continue
		}
		state := "down"
		if iface.Up {
			state = "up"
		}
		role := iface.Role
		switch iface.Role {
		case "wan":
			wan++
			if iface.Up {
				wanUp++
			}
		case "lan":
			lan++
		default:
			role = "—"
		}
		ip := iface.IPv4
		if ip == "" {
			ip = "—"
		}
		lines = append(lines, fmt.Sprintf("%-10s %-4s %-18s %s", iface.Name, state, ip, role))
	}
	status := StatusOK
	if wanUp == 0 {
		status = StatusWarn
	}
	return Card{
		Title:   "Interfaces",
		Status:  status,
		Summary: fmt.Sprintf("%d up on WAN · %d WAN · %d LAN", wanUp, wan, lan),
		Lines:   lines,
	}
}

// firewallCard summarises the active firewall's posture.
func firewallCard(snap Snapshot) Card {
	fw := snap.Firewall
	if fw.Backend == "" {
		return Card{
			Title:   "Firewall",
			Status:  StatusWarn,
			Summary: "no firewall backend detected",
		}
	}
	if fw.Reason != "" {
		return Card{
			Title:   "Firewall",
			Status:  StatusUnknown,
			Summary: fw.Backend + " · " + fw.Reason,
			Lines:   []string{"backend: " + fw.Backend},
		}
	}
	status := StatusOK
	if !fw.Active {
		status = StatusWarn
	}
	lines := []string{"backend: " + fw.Backend}
	if fw.Rules >= 0 {
		lines = append(lines, "rules:   "+strconv.Itoa(fw.Rules))
	}
	lines = append(lines, "NAT:     "+yesNo(fw.Masquerade))
	return Card{
		Title:   "Firewall",
		Status:  status,
		Summary: fw.Summary,
		Lines:   lines,
	}
}

// trafficCard shows the live per-interface throughput derived from two
// snapshots. With only one reading it says so rather than inventing a rate.
func trafficCard(snap Snapshot, prev *Snapshot) Card {
	rates := Throughputs(prev, &snap)
	if len(rates) == 0 {
		return Card{
			Title:   "Traffic",
			Status:  StatusInfo,
			Summary: "measuring…",
			Lines:   []string{"waiting for a second reading"},
		}
	}
	lines := make([]string, 0, len(rates))
	var totalRx, totalTx float64
	for _, r := range rates {
		totalRx += r.RxBps
		totalTx += r.TxBps
		lines = append(lines, fmt.Sprintf("%-10s ↓ %-10s ↑ %s",
			r.Name, humanRate(r.RxBps), humanRate(r.TxBps)))
	}
	return Card{
		Title:   "Traffic",
		Status:  StatusInfo,
		Summary: fmt.Sprintf("↓ %s  ↑ %s total", humanRate(totalRx), humanRate(totalTx)),
		Lines:   lines,
	}
}

// Throughputs derives the per-interface rate between two snapshots. It returns
// nil when there is no earlier reading, no elapsed time, or the counters
// cannot be paired — a throughput needs two points in time.
func Throughputs(prev, cur *Snapshot) []Throughput {
	if prev == nil {
		return nil
	}
	seconds := cur.At.Sub(prev.At).Seconds()
	if seconds <= 0 {
		return nil
	}
	before := map[string]Counter{}
	for _, c := range prev.Counters {
		before[c.Name] = c
	}
	out := make([]Throughput, 0, len(cur.Counters))
	for _, c := range cur.Counters {
		if c.Name == "lo" {
			continue
		}
		p, ok := before[c.Name]
		if !ok {
			continue
		}
		out = append(out, Throughput{
			Name:  c.Name,
			RxBps: rate(p.RxBytes, c.RxBytes, seconds),
			TxBps: rate(p.TxBytes, c.TxBytes, seconds),
		})
	}
	return out
}

// rate turns two counter readings into bytes per second, guarding the counter
// reset (a smaller current value) that a reboot or a wrap produces.
func rate(before, after uint64, seconds float64) float64 {
	if after < before {
		return 0
	}
	return float64(after-before) / seconds
}

// dhcpCard summarises the DHCP server and its lease count.
func dhcpCard(snap Snapshot) Card {
	d := snap.DHCP
	if d.Server == "" {
		return Card{
			Title:   "DHCP",
			Status:  StatusInfo,
			Summary: "no DHCP server detected",
		}
	}
	if d.Reason != "" {
		return Card{
			Title:   "DHCP",
			Status:  StatusUnknown,
			Summary: d.Server + " · " + d.Reason,
			Lines:   []string{"server: " + d.Server},
		}
	}
	status := StatusOK
	state := "active"
	if !d.Active {
		status = StatusWarn
		state = "stopped"
	}
	lines := []string{"server: " + d.Server, "state:  " + state}
	if d.Leases >= 0 {
		lines = append(lines, "leases: "+strconv.Itoa(d.Leases))
	}
	summary := d.Server + " · " + state
	if d.Leases >= 0 {
		summary += " · " + strconv.Itoa(d.Leases) + " leases"
	}
	return Card{Title: "DHCP", Status: status, Summary: summary, Lines: lines}
}

// vpnCard summarises the WireGuard interfaces, their peers, and whether a
// headscale control plane is present.
func vpnCard(snap Snapshot) Card {
	v := snap.VPN
	if v.Reason != "" {
		return Card{
			Title:   "VPN",
			Status:  StatusUnknown,
			Summary: v.Reason,
		}
	}
	lines := make([]string, 0, len(v.Interfaces)+1)
	peers := 0
	for _, iface := range v.Interfaces {
		peers += iface.Peers
		lines = append(lines, fmt.Sprintf("%-8s %d peers · %d handshaked",
			iface.Name, iface.Peers, iface.Handshakes))
	}
	if v.Headscale {
		lines = append(lines, "headscale: present")
	}
	if len(v.Interfaces) == 0 {
		status := StatusInfo
		summary := "no WireGuard interface"
		if v.Headscale {
			summary += " · headscale present"
		}
		return Card{Title: "VPN", Status: status, Summary: summary, Lines: lines}
	}
	summary := fmt.Sprintf("%d WireGuard · %d peers", len(v.Interfaces), peers)
	if v.Headscale {
		summary += " · headscale"
	}
	return Card{Title: "VPN", Status: StatusOK, Summary: summary, Lines: lines}
}

// updatesCard summarises the pending updates as tui-update reported them.
func updatesCard(snap Snapshot) Card {
	u := snap.Updates
	if !u.Available {
		reason := u.Reason
		if reason == "" {
			reason = "tui-update not installed"
		}
		return Card{Title: "Updates", Status: StatusUnknown, Summary: reason}
	}
	if u.Pending == 0 {
		return Card{Title: "Updates", Status: StatusOK, Summary: "up to date",
			Lines: []string{"pending:  0"}}
	}
	status := StatusInfo
	summary := strconv.Itoa(u.Pending) + " pending"
	lines := []string{"pending:  " + strconv.Itoa(u.Pending)}
	if u.Security > 0 {
		status = StatusWarn
		summary += " · " + strconv.Itoa(u.Security) + " security"
		lines = append(lines, "security: "+strconv.Itoa(u.Security))
	}
	return Card{Title: "Updates", Status: status, Summary: summary, Lines: lines}
}

// humanRate renders a bytes-per-second rate in the largest unit that keeps it
// short.
func humanRate(bps float64) string {
	const unit = 1024.0
	switch {
	case bps < unit:
		return fmt.Sprintf("%.0f B/s", bps)
	case bps < unit*unit:
		return fmt.Sprintf("%.1f KB/s", bps/unit)
	case bps < unit*unit*unit:
		return fmt.Sprintf("%.1f MB/s", bps/(unit*unit))
	default:
		return fmt.Sprintf("%.1f GB/s", bps/(unit*unit*unit))
	}
}

// yesNo renders a bool the way the cards read.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
