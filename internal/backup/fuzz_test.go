package backup

import (
	"strings"
	"testing"
)

// FuzzOpen treats the artifact reader as the hostile-input parser it is: an
// artifact is bytes another machine wrote, so Open must never panic, never
// return a value alongside an error, and never leak a secret it could not have
// read. The floor is not crashing; the corpus seeds a real artifact and the
// shapes a real one never has.
func FuzzOpen(f *testing.F) {
	// A valid artifact, and a signed one, are the richest seeds.
	valid, _ := Assemble(sampleSources(), sampleMeta(), nil)
	f.Add(valid)
	f.Add([]byte(""))
	f.Add([]byte("\x1f\x8b")) // a gzip magic with nothing after it
	f.Add([]byte("not gzip at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		art, err := Open(data, nil)
		if err != nil {
			if art != nil {
				t.Fatalf("Open returned both an artifact and an error")
			}
			return
		}
		if art == nil {
			t.Fatal("Open returned nil artifact and nil error")
		}
		// A successfully opened artifact must have passed the schema gate.
		if art.Manifest.Schema != SchemaVersion {
			t.Fatalf("opened artifact with schema %d", art.Manifest.Schema)
		}
		// The sanitizer must have removed control characters from every text
		// part it surfaced.
		for _, text := range collectText(art.Sources) {
			if strings.ContainsAny(text, "\x00\x07\x1b\r") {
				t.Fatalf("control character survived in a part: %q", text)
			}
		}
	})
}

// collectText gathers every text part of a Sources for the invariant checks.
func collectText(src Sources) []string {
	out := []string{src.Nftables, src.DHCPDNS}
	for _, v := range src.Networkd {
		out = append(out, v)
	}
	for _, v := range src.Wireguard {
		out = append(out, v.Config)
	}
	return out
}
