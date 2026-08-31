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

// TestRunReportDemo checks the half of the block this tool owns. The kit's own
// tests cover the machine facts and the scrubbing; what has to be right here is
// that --demo says demo, that the imitated backend is named rather than the
// name the fake gives itself, and that nothing on the machine was read to
// produce any of it.
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
		"demo backend: " + listerName + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, toolName+" ") {
		t.Errorf("report should start with the tool name:\n%s", got)
	}
}

// TestRunReportLive checks that a live run names the backend the manifest
// declares, and says the run was live.
func TestRunReportLive(t *testing.T) {
	var out strings.Builder
	if err := runReport(baseConfig(), options{report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{"backend: " + backendName, "mode: live\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
}

// TestRunReportSurvivesAMissingBackend is the case a report exists for: a
// machine the tool cannot drive at all. It must still produce a block, with
// the failure as one of its lines and the path in that failure scrubbed.
func TestRunReportSurvivesAMissingBackend(t *testing.T) {
	cfg := baseConfig()
	// "ana" is one of the family's stand-in names, which the secret scanner
	// knows is invented rather than captured from somebody's machine.
	cfg.Set(keyDir, "/home/ana/not-a-directory")

	var out strings.Builder
	if err := runReport(cfg, options{report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "backend error: ") {
		t.Errorf("report should carry the reason no backend was built:\n%s", got)
	}
	if strings.Contains(got, "/home/") {
		t.Errorf("the backend error was not scrubbed:\n%s", got)
	}
}

// TestRunReportKeepsItsPrivacyPromise is the assertion the bug form depends on.
// The block is pasted into a public issue, so the user name, the home path and
// the host name appearing in it would be a disclosure, not a cosmetic slip.
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
// fixed by the kit and carry nothing about the machine, so only values are
// looked at; the three values a name can legitimately collide with — the
// distribution, the kernel and the terminal, none of which this tool supplies
// — are skipped, because a machine called "fedora" running Fedora is not a
// leak and failing on it would be a test of the machine rather than the code.
func assertAbsent(t *testing.T, block, name, what string) {
	t.Helper()
	if name == "" {
		return
	}
	for _, line := range strings.Split(block, "\n") {
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			// The headline, which carries only the tool and the versions.
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

// TestScrubHome covers the one value this tool passes into the block that
// could name its user: the directory it was asked to list.
func TestScrubHome(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"a home path", "/home/ana/photos is not a directory",
			"~elsewhere~ is not a directory"},
		{"root's home", "/root/tmp is not a directory",
			"~elsewhere~ is not a directory"},
		{"a path that names nobody", "/srv/data is not a directory",
			"/srv/data is not a directory"},
		{"nothing to scrub", "touch was not found", "touch was not found"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubHome(tc.in); got != tc.want {
				t.Errorf("scrubHome(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
