package tool

import (
	"reflect"
	"testing"

	"github.com/tui-tools/tui-kit/runner"
)

// The family rule is that every package turning bytes it did not write into
// values the tool acts on carries a Go native fuzz test, seeded from the
// package's testdata — see
// https://github.com/tui-tools/tui-kit/blob/main/templates/FUZZING.md and the
// worked example in tui-kit/pkgmgr/fuzz_test.go.
//
// This template parses nothing: it lists a directory. What it does have is the
// step every tool in the family has, where a name that came from outside
// becomes an argv the user is about to confirm, so that is what the target
// below covers. Replace it with one target per parser once `internal/tool` is
// your subject, and keep asserting invariants rather than outputs: what a
// caller is allowed to assume for any input at all.

// FuzzBuildCommand feeds arbitrary item paths through the one place in the
// tool that builds a command line. Whatever comes back is what the confirm
// dialog will show and the runner will execute, so the shape of it has to hold
// for every input: a failure returns nothing runnable, and a success returns
// exactly the argv the preview promises.
func FuzzBuildCommand(f *testing.F) {
	f.Add("/srv/demo/notes.txt")
	f.Add("notes.txt")
	// The shapes a directory listing never has, and the ones an unusual file
	// name does: nothing at all, a separator on its own, whitespace, a
	// newline that would break a preview into two lines, something that looks
	// like a flag, a quote, a NUL.
	f.Add("")
	f.Add("/")
	f.Add(" ")
	f.Add("a b")
	f.Add("a\nb")
	f.Add("--force")
	f.Add("a'b\"c")
	f.Add("a\x00b")

	spec, ok := ActionFor("t")
	if !ok {
		f.Fatal("no action bound to \"t\"")
	}

	f.Fuzz(func(t *testing.T, path string) {
		cmd, err := BuildCommand(spec, path)
		if err != nil {
			if !reflect.DeepEqual(cmd, runner.Command{}) {
				t.Fatalf("failed with a non-empty command: %+v", cmd)
			}
			return
		}
		if path == "" {
			t.Fatal("built a command with nothing selected")
		}
		if len(cmd.Argv) == 0 || cmd.Argv[0] == "" {
			t.Fatalf("argv has no program: %q", cmd.Argv)
		}
		// The path arrives as one argument, never split and never dropped:
		// the preview the user reads has to name the file that will change.
		if len(cmd.Argv) != 2 || cmd.Argv[1] != path {
			t.Fatalf("argv = %q, want the path as a single argument", cmd.Argv)
		}
		if cmd.Description == "" {
			t.Fatal("a command needs a description for the dialog title")
		}
	})
}
