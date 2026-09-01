package router

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// This file is the exec half of the roles wizard and the power keys on the
// real backend. Every command built here is previewed by the same runner that
// executes it, so the confirm dialog's promise — the command you were shown
// is the command that ran — holds for the cockpit's few mutations exactly as
// it does across the family.

// nicsSearchPaths is where the router profile installs omarchy-router-nics.
var nicsSearchPaths = []string{
	"/usr/bin/omarchy-router-nics", "/usr/local/bin/omarchy-router-nics",
	"/usr/share/omarchy/bin/omarchy-router-nics",
}

// systemdRunSearchPaths is where systemd-run lives.
var systemdRunSearchPaths = []string{"/usr/bin/systemd-run", "/bin/systemd-run"}

// sudoPrefix recovers the resolved escalation prefix from the runners the
// backend was built with, so the mutation runners escalate exactly the way
// the read runners were configured to.
func (r *Real) sudoPrefix() []string {
	for _, rr := range []*runner.Runner{r.systemctl, r.ip, r.nft, r.wg} {
		if rr != nil && len(rr.Privilege) > 0 {
			return rr.Privilege
		}
	}
	return nil
}

// mutRunner builds a runner for one mutation binary, escalating with the
// backend's sudo prefix.
func (r *Real) mutRunner(bin string, searchPaths ...string) (*runner.Runner, error) {
	return runner.New(runner.Options{
		Bin: bin, SearchPaths: searchPaths,
		SudoPrefix: r.sudoPrefix(), PrivilegedReads: &privileged,
	})
}

// stagingPath is where the wizard stages a file before root installs it: the
// user's own cache directory, so no other user can race the staged content
// the way a predictable /tmp name could be raced.
func stagingPath(name string) (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no cache directory to stage into: %w", err)
	}
	dir := filepath.Join(cache, "tui-router")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// stagedRolesName and stagedPrevName are the fixed staging file names, so the
// previewed install command names the exact file the confirmed install reads.
const (
	stagedRolesName = "roles.conf.staged"
	stagedPrevName  = "roles.conf.prev.staged"
)

// readRoles reads the role assignment state: is this a router-profile host,
// does roles.conf exist, and what does it assign. It is a pure file read.
func (r *Real) readRoles() RolesStatus {
	var s RolesStatus
	if info, err := os.Stat(RolesDir); err == nil && info.IsDir() {
		s.ProfilePresent = true
	}
	data, err := os.ReadFile(RolesConfPath)
	if err != nil {
		return s
	}
	s.ConfPresent = true
	s.Content = string(data)
	s.Parsed = ParseRolesConf(s.Content)
	return s
}

// NicsPreview runs `omarchy-router-nics --preview`, the profile's own
// read-only render of the role→device mapping. --preview only reads
// roles.conf (world-readable), so it runs unprivileged.
func (r *Real) NicsPreview(ctx context.Context) (string, error) {
	nics, err := runner.New(runner.Options{
		Bin: "omarchy-router-nics", SearchPaths: nicsSearchPaths,
		SudoPrefix: r.sudoPrefix(), PrivilegedReads: &unprivileged,
	})
	if err != nil {
		return "", err
	}
	return nics.Read(ctx, "omarchy-router-nics", "--preview")
}

// installCommand is the previewed roles.conf install for one staged file.
func installCommand(staged, target string) runner.Command {
	return runner.Command{
		Argv:        []string{"install", "-m", "644", staged, target},
		Description: "install " + filepath.Base(target),
	}
}

// WritePlan previews the roles.conf install for the given content. The
// staging path is fixed, so the preview shown is the command run.
func (r *Real) WritePlan(content string) WritePlan {
	staged, err := stagingPath(stagedRolesName)
	if err != nil {
		staged = "<staging unavailable: " + err.Error() + ">"
	}
	cmd := installCommand(staged, RolesConfPath)
	install, err := r.mutRunner("install", "/usr/bin/install", "/bin/install")
	if err != nil {
		return WritePlan{Preview: cmd.String()}
	}
	return WritePlan{Preview: install.Preview(cmd)}
}

// WriteRoles stages the content and installs it as roles.conf, mode 0644 —
// exactly the command WritePlan previewed.
func (r *Real) WriteRoles(ctx context.Context, content string) error {
	staged, err := stagingPath(stagedRolesName)
	if err != nil {
		return err
	}
	if err := os.WriteFile(staged, []byte(content), 0o600); err != nil {
		return err
	}
	install, err := r.mutRunner("install", "/usr/bin/install", "/bin/install")
	if err != nil {
		return err
	}
	_, err = install.Run(ctx, installCommand(staged, RolesConfPath))
	return err
}

// ApplyPlan previews the whole apply-with-revert sequence the second confirm
// covers: stage the previous assignment, arm the timed revert, re-apply the
// mapping — and the cancel that disarms the revert afterwards.
func (r *Real) ApplyPlan() ApplyPlan {
	plan := ApplyPlan{HasSystemdRun: runner.Available("systemd-run", systemdRunSearchPaths...)}

	stagedPrev, err := stagingPath(stagedPrevName)
	if err != nil {
		stagedPrev = "<staging unavailable>"
	}
	stageCmd := installCommand(stagedPrev, RolesPrevPath)
	if install, err := r.mutRunner("install", "/usr/bin/install", "/bin/install"); err == nil {
		plan.StagePreview = install.Preview(stageCmd)
	} else {
		plan.StagePreview = stageCmd.String()
	}

	if plan.HasSystemdRun {
		schedCmd := runner.Command{Argv: RevertScheduleArgv(RevertDelay)}
		if sd, err := r.mutRunner("systemd-run", systemdRunSearchPaths...); err == nil {
			plan.SchedulePreview = sd.Preview(schedCmd)
		} else {
			plan.SchedulePreview = schedCmd.String()
		}
	} else {
		plan.ManualRevert = ManualRevertInstructions()
	}

	applyCmd := runner.Command{
		Argv: []string{"omarchy-router-nics", "--apply"}, Destructive: true}
	if nics, err := r.mutRunner("omarchy-router-nics", nicsSearchPaths...); err == nil {
		plan.ApplyPreview = nics.Preview(applyCmd)
	} else {
		plan.ApplyPreview = applyCmd.String()
	}

	cancelCmd := runner.Command{Argv: CancelRevertArgv()}
	if r.systemctl != nil {
		plan.CancelPreview = r.systemctl.Preview(cancelCmd)
	} else {
		plan.CancelPreview = cancelCmd.String()
	}
	return plan
}

// ApplyRoles runs the previewed sequence: stage the previous roles.conf as
// the revert source, arm the timed revert when systemd-run is present, then
// re-run the profile's network script for the new mapping. The revert is
// armed BEFORE the apply, so a session the apply cuts off still gets its
// assignment back two minutes later.
func (r *Real) ApplyRoles(ctx context.Context, prevContent string) (ApplyResult, error) {
	var result ApplyResult

	stagedPrev, err := stagingPath(stagedPrevName)
	if err != nil {
		return result, err
	}
	if err := os.WriteFile(stagedPrev, []byte(prevContent), 0o600); err != nil {
		return result, err
	}
	install, err := r.mutRunner("install", "/usr/bin/install", "/bin/install")
	if err != nil {
		return result, err
	}
	if _, err := install.Run(ctx, installCommand(stagedPrev, RolesPrevPath)); err != nil {
		return result, fmt.Errorf("staging the revert copy: %w", err)
	}

	if runner.Available("systemd-run", systemdRunSearchPaths...) {
		sd, err := r.mutRunner("systemd-run", systemdRunSearchPaths...)
		if err == nil {
			if _, err := sd.Run(ctx, runner.Command{Argv: RevertScheduleArgv(RevertDelay)}); err != nil {
				return result, fmt.Errorf("arming the revert timer: %w", err)
			}
			result.RevertScheduled = true
		}
	}

	nics, err := r.mutRunner("omarchy-router-nics", nicsSearchPaths...)
	if err != nil {
		return result, err
	}
	out, err := nics.Run(ctx, runner.Command{
		Argv: []string{"omarchy-router-nics", "--apply"}, Destructive: true})
	result.Output = strings.TrimSpace(out)
	return result, err
}

// CancelRevert disarms the timed revert: the operator confirmed the new
// assignment kept them connected, so the previous one must not come back.
func (r *Real) CancelRevert(ctx context.Context) error {
	systemctl := r.systemctl
	if systemctl == nil {
		var err error
		systemctl, err = r.mutRunner("systemctl", "/usr/bin/systemctl", "/bin/systemctl")
		if err != nil {
			return err
		}
	}
	_, err := systemctl.Run(ctx, runner.Command{Argv: CancelRevertArgv()})
	return err
}

// rebootCommand and poweroffCommand are the cockpit's two power commands.
var (
	rebootCommand   = runner.Command{Argv: []string{"systemctl", "reboot"}, Destructive: true}
	poweroffCommand = runner.Command{Argv: []string{"systemctl", "poweroff"}, Destructive: true}
)

// powerRunner returns the systemctl runner the power keys use.
func (r *Real) powerRunner() (*runner.Runner, error) {
	if r.systemctl != nil {
		return r.systemctl, nil
	}
	return r.mutRunner("systemctl", "/usr/bin/systemctl", "/bin/systemctl")
}

// RebootPreview is the exact command the reboot confirm shows.
func (r *Real) RebootPreview() string {
	if s, err := r.powerRunner(); err == nil {
		return s.Preview(rebootCommand)
	}
	return rebootCommand.String()
}

// Reboot runs the previewed reboot.
func (r *Real) Reboot(ctx context.Context) error {
	s, err := r.powerRunner()
	if err != nil {
		return err
	}
	_, err = s.Run(ctx, rebootCommand)
	return err
}

// PoweroffPreview is the exact command the poweroff confirm shows.
func (r *Real) PoweroffPreview() string {
	if s, err := r.powerRunner(); err == nil {
		return s.Preview(poweroffCommand)
	}
	return poweroffCommand.String()
}

// Poweroff runs the previewed poweroff.
func (r *Real) Poweroff(ctx context.Context) error {
	s, err := r.powerRunner()
	if err != nil {
		return err
	}
	_, err = s.Run(ctx, poweroffCommand)
	return err
}
