package backup

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Signer produces a detached signature over the checksum file. It is an
// interface so the mechanism is pluggable and so a test can drive the whole
// signed path without an external tool. Signing is always optional: a nil
// Signer means no SIGNATURE is written, and integrity still rests on the
// unconditional checksums.
type Signer interface {
	// Sign returns a detached signature over data. The implementation reads
	// key material it was given; it never writes any secret anywhere.
	Sign(data []byte) ([]byte, error)
	// KeyID names the key in the manifest-independent SIGNATURE header, so a
	// verifier can tell which public key to expect.
	KeyID() string
}

// Verifier checks a detached signature over the checksum file. A nil Verifier
// on restore means the signature, if present, is not checked (integrity still
// is); a non-nil one makes a valid signature mandatory.
type Verifier interface {
	Verify(data, sig []byte) error
}

// signaturePrefix marks the one-line detached signature format the tool writes:
// a fixed tag, the algorithm, the key id, and the base64 signature. It is a
// deliberately small, self-describing shape rather than a general container.
const signaturePrefix = "tui-router-sig"

// ed25519Signer signs with an Ed25519 secret key. The key is held only in
// memory for the life of the process and never serialized; only the resulting
// public signature is written, into the detached SIGNATURE file.
type ed25519Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

// NewEd25519Signer builds a Signer from a raw Ed25519 seed (32 bytes) or a full
// expanded key (64 bytes). The caller reads these bytes from the operator's key
// file; this constructor keeps them in memory only and writes nothing.
func NewEd25519Signer(keyBytes []byte, keyID string) (Signer, error) {
	var priv ed25519.PrivateKey
	switch len(keyBytes) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(keyBytes)
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(append([]byte(nil), keyBytes...))
	default:
		return nil, fmt.Errorf("backup: an Ed25519 key is %d or %d bytes, got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(keyBytes))
	}
	return &ed25519Signer{priv: priv, keyID: keyID}, nil
}

func (s *ed25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, data), nil
}

func (s *ed25519Signer) KeyID() string { return s.keyID }

// ed25519Verifier checks an Ed25519 signature against a public key.
type ed25519Verifier struct {
	pub ed25519.PublicKey
}

// NewEd25519Verifier builds a Verifier from a raw 32-byte Ed25519 public key.
func NewEd25519Verifier(pubBytes []byte) (Verifier, error) {
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("backup: an Ed25519 public key is %d bytes, got %d",
			ed25519.PublicKeySize, len(pubBytes))
	}
	return &ed25519Verifier{pub: ed25519.PublicKey(append([]byte(nil), pubBytes...))}, nil
}

func (v *ed25519Verifier) Verify(data, sig []byte) error {
	if !ed25519.Verify(v.pub, data, sig) {
		return errors.New("backup: signature does not verify against the given public key")
	}
	return nil
}

// encodeSignature renders a detached signature as the one-line SIGNATURE file.
func encodeSignature(sig []byte, keyID string) []byte {
	if keyID == "" {
		keyID = "-"
	}
	return []byte(strings.Join([]string{
		signaturePrefix, "ed25519", keyID,
		base64.StdEncoding.EncodeToString(sig),
	}, " ") + "\n")
}

// decodeSignature parses the one-line SIGNATURE file back into raw signature
// bytes. It treats the file as hostile input: a shape it does not recognize is
// an error, never a panic.
func decodeSignature(raw []byte) (sig []byte, keyID string, err error) {
	fields := strings.Fields(strings.TrimSpace(string(raw)))
	if len(fields) != 4 || fields[0] != signaturePrefix || fields[1] != "ed25519" {
		return nil, "", errors.New("backup: SIGNATURE is not a recognized detached signature")
	}
	sig, err = base64.StdEncoding.DecodeString(fields[3])
	if err != nil {
		return nil, "", fmt.Errorf("backup: SIGNATURE is not valid base64: %w", err)
	}
	return sig, fields[2], nil
}
