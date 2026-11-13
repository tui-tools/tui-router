package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/tui-tools/tui-router/internal/backup"
	"github.com/tui-tools/tui-router/internal/router"
)

// keyStoreFor is where export and restore find the machine's keys. It is a
// variable so a test can point both at a temporary directory, which is how a
// "same machine" and a "rebuilt machine" are told apart without root.
var keyStoreFor = func(backend router.BackupBackend) router.KeyStore {
	return backend.SigningKeys()
}

// verification is how a restore's signature check went: which key verified
// the artifact, if any, and how that key was chosen.
type verification struct {
	// key verified the signature; its Path is empty when nothing did.
	key router.TrustedKey
	// explicit reports that the operator named the key (--verify, or the
	// cockpit's key prompt) rather than it being one the machine trusts.
	explicit bool
	// problems are trusted-key files that were skipped, and why.
	problems []string
}

// verified reports whether a key verified the artifact.
func (v verification) verified() bool { return v.key.Path != "" }

// openVerified opens an artifact and checks its signature: against the public
// key in verifyKey when one is named, otherwise against every key the machine
// trusts — its own, and the operator's trusted-keys directory.
//
// The public key file that may sit beside the artifact is never among them. It
// travels with the artifact, so whoever could change the one could change the
// other: it proves nothing until the operator has compared its fingerprint
// with one they kept elsewhere and named it themselves.
func openVerified(data []byte, verifyKey string, store router.KeyStore) (
	*backup.Artifact, verification, error) {
	if verifyKey != "" {
		pub, err := readPublicKeyFile(verifyKey)
		if err != nil {
			return nil, verification{}, err
		}
		verifier, err := backup.NewEd25519Verifier(pub)
		if err != nil {
			return nil, verification{}, err
		}
		art, err := backup.Open(data, verifier)
		if err != nil {
			return nil, verification{}, err
		}
		return art, verification{key: router.TrustedKey{Path: verifyKey, Public: pub},
			explicit: true}, nil
	}

	art, err := backup.Open(data, nil)
	if err != nil {
		// A tampered, truncated or malformed artifact is refused here.
		return nil, verification{}, err
	}
	if !art.Signed || store == nil {
		return art, verification{}, nil
	}
	keys, problems := store.Trusted()
	for _, key := range keys {
		verifier, err := backup.NewEd25519Verifier(key.Public)
		if err != nil {
			continue
		}
		if checked, err := backup.Open(data, verifier); err == nil && checked.SignatureVerified {
			return checked, verification{key: key, problems: problems}, nil
		}
	}
	return art, verification{problems: problems}, nil
}

// readPublicKeyFile reads a public key the operator named.
func readPublicKeyFile(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the key path is one the operator named
	if err != nil {
		return nil, fmt.Errorf("reading the public key: %w", err)
	}
	return backup.ParsePublicKey(raw)
}

// besidePubPath is where export writes an artifact's public key.
func besidePubPath(artifactPath string) string { return artifactPath + ".pub" }

// besideKey reads the public key export left beside an artifact, when there is
// one. It is shown, with its fingerprint, as something to compare; it is never
// used unless the operator names it.
func besideKey(artifactPath string) (router.TrustedKey, bool) {
	path := besidePubPath(artifactPath)
	pub, err := readPublicKeyFile(path)
	if err != nil {
		return router.TrustedKey{}, false
	}
	return router.TrustedKey{Path: path, Public: pub}, true
}

// fingerprintRe is the only shape of a SIGNATURE key id worth repeating: the
// file is untrusted input, so anything else is not printed.
var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// signatureStatus renders the signature line of the restore preview. Only a
// verified signature is trust; every other case says plainly that it is not.
func signatureStatus(art *backup.Artifact, v verification) string {
	switch {
	case v.verified() && v.explicit:
		return "present and verified against the given public key " + v.key.Path +
			" (" + v.key.Fingerprint() + ")"
	case v.verified():
		return "present and verified against this machine's trusted key " + v.key.Path +
			" (" + v.key.Fingerprint() + ")"
	case art.Signed && fingerprintRe.MatchString(art.SignatureKeyID):
		return "NOT VERIFIED — signed, but no key this machine trusts verifies it " +
			"(it names " + art.SignatureKeyID + ")"
	case art.Signed:
		return "NOT VERIFIED — signed, but no key this machine trusts verifies it"
	default:
		return "NOT VERIFIED — the artifact is unsigned"
	}
}

// unverifiedRefusal is the error a restore returns for an artifact whose
// signature was not verified when the operator did not opt in to trusting it.
func unverifiedRefusal(art *backup.Artifact, store router.KeyStore) string {
	what := "the artifact is unsigned"
	if art.Signed {
		what = "the artifact is signed, but not by this machine's key or a key in " +
			trustedKeysDir(store)
	}
	return "restore refused: " + what + ".\n" +
		"Its checksums prove only that the file is intact, not who wrote it: anyone who\n" +
		"could edit the file could recompute them, and a restore writes config that root reads.\n" +
		"Pass --verify PUBKEY with the public key of the machine that exported it, from a copy\n" +
		"kept apart from the backup (the .pub beside the artifact travels with it and proves\n" +
		"nothing on its own), place that key in " + trustedKeysDir(store) + ",\n" +
		"or pass --allow-unsigned if you trust this file as it is (--dry-run previews it either way)."
}

// trustedKeysDir names the directory of keys a restore trusts.
func trustedKeysDir(store router.KeyStore) string {
	if store == nil {
		return router.SigningKeyDir + "/" + router.TrustedKeysName
	}
	return store.TrustedDir()
}

// errNoKeyCreated is the export refusal when the operator declined the key.
var errNoKeyCreated = errors.New("no signing key was created and nothing was exported.\n" +
	"Pass --create-key to create it without the question, --no-sign for an unsigned\n" +
	"artifact (restoring it will need --allow-unsigned), or --sign KEY to sign with your own key")

// writeArtifact writes the artifact, and — when it is signed — its public key
// beside it as <artifact>.pub, so the key can be copied somewhere other than
// the backup. It returns the public key's path, empty for an unsigned one.
func writeArtifact(path string, data []byte, signer backup.Signer) (string, error) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("writing the artifact: %w", err)
	}
	if signer == nil {
		return "", nil
	}
	pubPath := besidePubPath(path)
	if err := os.WriteFile(pubPath, backup.EncodePublicKey(signer.Public()), 0o644); err != nil { //nolint:gosec // a public key is meant to be read
		return "", fmt.Errorf("writing the public key: %w", err)
	}
	return pubPath, nil
}

// signedSummary is what an export says about its signature: which key, where
// its public half was written, and why its fingerprint is worth keeping.
func signedSummary(signer backup.Signer, pubPath, signedWith string) string {
	return "signed with " + signedWith + "\n" +
		"public key: " + pubPath + "  " + backup.Fingerprint(signer.Public()) + "\n" +
		"Keep that fingerprint somewhere other than the backup. A restore on this machine\n" +
		"verifies on its own; on a rebuilt or another machine you will verify with this key,\n" +
		"and the fingerprint is how you know the copy you have is the right one."
}

// signingLimits is the plain statement of what the signature does and does
// not protect, shown wherever the operator decides about it.
const signingLimits = "The signature detects any change made by someone without this machine's " +
	"private key. It cannot help if this machine (root) was already compromised when it " +
	"exported, and a rebuilt machine needs the public key from somewhere other than the backup."

// createKeyBlock describes the key creation an export is about to run.
func createKeyBlock(store router.KeyStore, plan *router.KeyCreation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "This machine has no backup signing key yet. Exports are signed by default,\n"+
		"so this one first creates it in %s (fingerprint %s):\n",
		store.Location(), backup.Fingerprint(plan.Public))
	for _, step := range plan.Steps {
		fmt.Fprintf(&b, "  $ %s\n", step.Preview)
	}
	b.WriteString("The private key is written through stdin, never shown, and stays readable by root only.")
	return b.String()
}

// createLocalKey runs the first-export key creation for the command: the plan
// is printed, and created only on a typed yes or --create-key.
func createLocalKey(ctx context.Context, store router.KeyStore, preConfirmed bool,
	readLine func() string, out func(string)) (backup.Signer, error) {
	plan, err := store.PlanCreate()
	if err != nil {
		return nil, err
	}
	out(createKeyBlock(store, plan) + "\n")
	if !preConfirmed {
		out("Create it? Type 'yes' to continue: ")
		if strings.TrimSpace(readLine()) != "yes" {
			return nil, errNoKeyCreated
		}
	}
	signer, err := store.Create(ctx, plan)
	if err != nil {
		return nil, fmt.Errorf("creating the signing key: %w", err)
	}
	out("created the machine's signing key " + backup.Fingerprint(plan.Public) + "\n")
	return signer, nil
}
