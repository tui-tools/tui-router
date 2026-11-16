package router

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// withEtc points the real collector's file reads at an in-memory /etc, with
// denied naming the paths a run without root could not open. Nothing on the
// machine running the test is read.
func withEtc(t *testing.T, files fstest.MapFS, denied ...string) {
	t.Helper()
	isDenied := func(path string) bool {
		for _, d := range denied {
			if path == d {
				return true
			}
		}
		return false
	}
	rel := func(path string) string { return strings.TrimPrefix(path, "/") }
	prevFile, prevDir := readFile, readDir
	readFile = func(path string) ([]byte, error) {
		if isDenied(path) {
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
		}
		return fs.ReadFile(files, rel(path))
	}
	readDir = func(path string) ([]fs.DirEntry, error) {
		if isDenied(path) {
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
		}
		return fs.ReadDir(files, rel(path))
	}
	t.Cleanup(func() { readFile, readDir = prevFile, prevDir })
}

const collectWGConf = "[Interface]\nAddress = 10.0.0.1/24\nListenPort = 51820\n"

// TestCollectRefusesUnreadableWireguard is the lab finding: without root,
// /etc/wireguard cannot be listed. The collection must fail and name it, not
// return sources that merely lack WireGuard.
func TestCollectRefusesUnreadableWireguard(t *testing.T) {
	withEtc(t, fstest.MapFS{
		"etc/systemd/network/10-lan.network": {Data: []byte("[Match]\nName=lan0\n")},
		"etc/wireguard/wg0.conf":             {Data: []byte(collectWGConf)},
	}, wireguardEtcDir)

	_, err := (&Real{}).CollectSources(context.Background())
	var unreadable *UnreadableSourcesError
	if !errors.As(err, &unreadable) {
		t.Fatalf("err = %v, want an UnreadableSourcesError", err)
	}
	if len(unreadable.Unreadable) != 1 || unreadable.Unreadable[0] != "/etc/wireguard (permission denied)" {
		t.Errorf("unreadable = %q", unreadable.Unreadable)
	}
	if !strings.Contains(err.Error(), "Run tui-router as root") {
		t.Errorf("the error does not say to run as root: %v", err)
	}
}

// TestCollectRefusesOneUnreadableConfig: a listable directory with one file
// that cannot be read fails the same way, naming that file.
func TestCollectRefusesOneUnreadableConfig(t *testing.T) {
	withEtc(t, fstest.MapFS{
		"etc/wireguard/wg0.conf": {Data: []byte(collectWGConf)},
		"etc/wireguard/wg1.conf": {Data: []byte(collectWGConf)},
	}, "/etc/wireguard/wg1.conf", sysctlRouterConf)

	_, err := (&Real{}).CollectSources(context.Background())
	var unreadable *UnreadableSourcesError
	if !errors.As(err, &unreadable) {
		t.Fatalf("err = %v, want an UnreadableSourcesError", err)
	}
	got := strings.Join(unreadable.Unreadable, "|")
	want := "/etc/wireguard/wg1.conf (permission denied)|" + sysctlRouterConf + " (permission denied)"
	if got != want {
		t.Errorf("unreadable = %q, want %q", got, want)
	}
}

// TestCollectMissingIsNotAnError: locations that do not exist are simply
// absent; a router with no WireGuard still exports.
func TestCollectMissingIsNotAnError(t *testing.T) {
	withEtc(t, fstest.MapFS{
		"etc/wireguard/wg0.conf": {Data: []byte(collectWGConf)},
	})
	src, err := (&Real{}).CollectSources(context.Background())
	if err != nil {
		t.Fatalf("CollectSources: %v", err)
	}
	if _, ok := src.Wireguard["wg0"]; !ok || len(src.Networkd) != 0 || src.Sysctl != "" {
		t.Errorf("sources = %+v", src)
	}
}
