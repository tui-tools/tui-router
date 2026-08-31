package tool

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This file is the shape a tool's tests take in this family. Two things are
// worth asserting above everything else, and both are here:
//
//   - the command a key produces is exactly the command the preview shows;
//   - nothing runs that the user did not confirm.

func TestBuildCommand(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		path     string
		wantArgv []string
		wantErr  bool
	}{
		{
			name: "touch", key: "t", path: "/srv/demo/notes.txt",
			wantArgv: []string{"touch", "/srv/demo/notes.txt"},
		},
		{
			name: "no selection is an error, not an empty command",
			key:  "t", path: "", wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := ActionFor(tc.key)
			if !ok {
				t.Fatalf("no action bound to %q", tc.key)
			}
			cmd, err := BuildCommand(spec, tc.path)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildCommand: %v", err)
			}
			if !reflect.DeepEqual(cmd.Argv, tc.wantArgv) {
				t.Errorf("Argv = %q, want %q", cmd.Argv, tc.wantArgv)
			}
			if cmd.Description == "" {
				t.Error("a command needs a description for the dialog title")
			}
		})
	}
}

func TestActionKeysAreUnique(t *testing.T) {
	// A duplicate binding would silently shadow an action in the key handler.
	seen := map[string]Action{}
	for _, spec := range Actions {
		if other, ok := seen[spec.Key]; ok {
			t.Errorf("key %q is bound to both %q and %q", spec.Key, other, spec.Action)
		}
		seen[spec.Key] = spec.Action
		if spec.Label == "" || spec.Body == "" {
			t.Errorf("%q needs a label and a body for the confirm dialog", spec.Action)
		}
	}
}

func TestFakePreviewMatchesWhatRuns(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	spec, _ := ActionFor("t")
	cmd, err := f.Build(spec, "notes.txt")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	preview := f.Preview(cmd)
	if preview != "touch /srv/demo/notes.txt" {
		t.Errorf("preview = %q", preview)
	}

	if _, err := f.Run(ctx, cmd); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.Commands()) != 1 {
		t.Fatalf("ran %d commands, want 1", len(f.Commands()))
	}
	// The command that ran must be the one the preview showed, character for
	// character. This is the guarantee the whole family is built around.
	if got := f.Preview(f.Commands()[0]); got != preview {
		t.Errorf("ran %q, but the preview promised %q", got, preview)
	}
}

func TestFakeAppliesTheChange(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	modified := func(name string) time.Time {
		t.Helper()
		items, err := f.Items(ctx)
		if err != nil {
			t.Fatalf("Items: %v", err)
		}
		for _, item := range items {
			if item.Name == name {
				return item.Modified
			}
		}
		t.Fatalf("%s is missing from the demo data", name)
		return time.Time{}
	}

	before := modified("notes.txt")
	spec, _ := ActionFor("t")
	cmd, _ := f.Build(spec, "notes.txt")
	if _, err := f.Run(ctx, cmd); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !modified("notes.txt").After(before) {
		t.Error("the demo backend should apply the change to its own state")
	}
}

func TestFakeUnknownItem(t *testing.T) {
	f := NewFake()
	spec, _ := ActionFor("t")
	cmd, _ := f.Build(spec, "nope.txt")
	_, err := f.Run(context.Background(), cmd)
	if err == nil || !strings.Contains(err.Error(), "No such file") {
		t.Errorf("err = %v, want a not-found failure the way the real command reports it", err)
	}
}

func TestRealReadsADirectory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"b.txt", "a.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	backend, err := New(dir, nil)
	if err != nil {
		t.Skipf("touch is not available on this host: %v", err)
	}
	items, err := backend.Items(context.Background())
	if err != nil {
		t.Fatalf("Items: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3", len(items))
	}
	// Directories first, then names: the sort a tool chooses is part of what
	// it is for.
	if !items[0].Dir || items[0].Name != "sub" {
		t.Errorf("items[0] = %+v, want the directory first", items[0])
	}
	if items[1].Name != "a.txt" || items[2].Name != "b.txt" {
		t.Errorf("files are out of order: %+v", items[1:])
	}

	// The real backend resolves the name against the directory it lists, so
	// the preview shows a path the user can check.
	spec, _ := ActionFor("t")
	cmd, err := backend.Build(spec, "a.txt")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, want := cmd.Argv[1], filepath.Join(dir, "a.txt"); got != want {
		t.Errorf("argv[1] = %q, want %q", got, want)
	}
}

func TestNewRejectsANonDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := New(file, nil); err == nil {
		t.Error("expected an error for a path that is not a directory")
	}
}
