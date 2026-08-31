package main

import (
	"os"
	"os/user"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/config"
)

// baseConfig is the configuration a report is rendered against: the defaults,
// with nothing read from disk or from the environment.
func baseConfig() config.Config {
	return config.Config{Tool: toolName, Values: defaults()}
}

// TestRunReportDemo checks the half of the block this tool owns: that --demo
// says demo, names the backend the fake imitates, and reads nothing.
func TestRunReportDemo(t *testing.T) {
	var out strings.Builder
	opts := options{demo: true, report: true}
	if err := runReport(baseConfig(), opts, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"backend: demo\n",
		"mode: demo (sample data, the system was not read)\n",
		"demo backend: router\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, toolName+" ") {
		t.Errorf("report should start with the tool name:\n%s", got)
	}
}

// TestRunReportLive checks that a live run names the backend, says the run was
// live, and carries the backends and managing-tools lines this tool adds.
func TestRunReportLive(t *testing.T) {
	var out strings.Builder
	if err := runReport(baseConfig(), options{report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}
	got := out.String()
	for _, want := range []string{"backend: router", "mode: live\n", "backends: ", "managing tools: "} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
}

// TestRunReportKeepsItsPrivacyPromise is the assertion the bug form depends on:
// the block is pasted into a public issue, so a home path, the host name or the
// user name appearing in it would be a disclosure.
func TestRunReportKeepsItsPrivacyPromise(t *testing.T) {
	var out strings.Builder
	if err := runReport(baseConfig(), options{report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}
	got := out.String()

	if strings.Contains(got, "/home/") {
		t.Errorf("report carries a home path:\n%s", got)
	}
	if host, err := os.Hostname(); err == nil {
		assertAbsent(t, got, host, "host name")
	}
	if u, err := user.Current(); err == nil {
		assertAbsent(t, got, u.Username, "user name")
	}
}

// assertAbsent fails when name appears in a value of the block. The keys are
// fixed by the kit; the distro, kernel and term values can legitimately
// collide with a machine named after its distribution, so they are skipped.
func assertAbsent(t *testing.T, block, name, what string) {
	t.Helper()
	if name == "" {
		return
	}
	for _, line := range strings.Split(block, "\n") {
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			key, value = "", line
		}
		if key == "distro" || key == "kernel" || key == "term" {
			continue
		}
		if strings.Contains(value, name) {
			t.Errorf("report carries the %s %q on %q", what, name, line)
		}
	}
}
