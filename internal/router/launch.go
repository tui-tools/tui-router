package router

import (
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
)

// familyName is the shape of every tui-tools binary. A card only ever launches
// a name of this form, validated before it reaches exec, so the handoff can
// never run an arbitrary program.
var familyName = regexp.MustCompile(`^tui-[a-z]+$`)

// process adapts an *exec.Cmd to the Process interface, which is Bubble Tea's
// tea.ExecCommand method set. Bubble Tea calls SetStdin/SetStdout/SetStderr
// with the real terminal streams and then Run, which is how the child tool
// takes over the terminal while the cockpit is suspended.
type process struct {
	cmd *exec.Cmd
}

func (p *process) Run() error { return p.cmd.Run() }

func (p *process) SetStdin(r io.Reader) {
	if p.cmd.Stdin == nil {
		p.cmd.Stdin = r
	}
}

func (p *process) SetStdout(w io.Writer) {
	if p.cmd.Stdout == nil {
		p.cmd.Stdout = w
	}
}

func (p *process) SetStderr(w io.Writer) {
	if p.cmd.Stderr == nil {
		p.cmd.Stderr = w
	}
}

func (p *process) String() string { return strings.Join(p.cmd.Args, " ") }

// launchBinary resolves a family binary on PATH and wraps it for tea.Exec. The
// name is validated first, and the command is the resolved absolute path with
// no arguments: the child tool opens into its own default view. This is the
// launcher's mechanism, mirrored so the two hand off the terminal the same way.
func launchBinary(binary string) (Process, error) {
	if !familyName.MatchString(binary) {
		return nil, fmt.Errorf("%q is not a tui-tools binary name", binary)
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("%s is not installed", binary)
	}
	// G204: the argv is one element, the absolute path of a binary named
	// tui-<word> that was found on PATH, and no argument follows it.
	return &process{cmd: exec.Command(path)}, nil //nolint:gosec // validated name, no arguments
}

// available reports whether a family binary is on PATH, without building a
// command. The cards use it to say "not installed" instead of offering a
// handoff that would fail.
func available(binary string) bool {
	if !familyName.MatchString(binary) {
		return false
	}
	_, err := exec.LookPath(binary)
	return err == nil
}

// OnPath reports whether a managing tool's binary is on PATH. It is the same
// PATH lookup the cards use, exported so --report can name which tools are
// present without building a live backend (the exec boundary keeps LookPath in
// this package).
func OnPath(binary string) bool { return available(binary) }
