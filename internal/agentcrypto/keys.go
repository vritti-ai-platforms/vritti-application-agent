// Package agentcrypto holds the two keypairs the agent generates locally on first
// boot and never lets leave the machine:
//
//   - an Ed25519 signing key   → authenticates the agent TO cloud (agent→cloud)
//   - an X25519 sealing key     → the target operators seal human-entered secrets to
//
// The deployment's OWN keypair is the mirror image: cloud holds its private half and
// signs desired-state/commands; the agent only ever holds the deployment PUBLIC key and
// verifies with it (cloud→agent). That public key arrives during enrollment.
package agentcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

// Keys is the agent's local identity. Private halves are persisted 0600 and never sent.
type Keys struct {
	SignPub  ed25519.PublicKey  `json:"-"`
	SignPriv ed25519.PrivateKey `json:"-"`
	SealPub  [32]byte           `json:"-"`
	SealPriv [32]byte           `json:"-"`
}

// onDisk is the serialized form (base64) written to the key file.
type onDisk struct {
	SignPriv string `json:"signPriv"`
	SealPriv string `json:"sealPriv"`
}

// LoadOrCreate loads the agent keys from dir, generating and persisting them on first run.
func LoadOrCreate(dir string) (*Keys, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "agent-keys.json")

	if data, err := os.ReadFile(path); err == nil {
		var d onDisk
		if err := json.Unmarshal(data, &d); err != nil {
			return nil, fmt.Errorf("parse key file: %w", err)
		}
		return fromDisk(d)
	}

	keys, err := generate()
	if err != nil {
		return nil, err
	}
	d := onDisk{
		SignPriv: base64.StdEncoding.EncodeToString(keys.SignPriv),
		SealPriv: base64.StdEncoding.EncodeToString(keys.SealPriv[:]),
	}
	blob, _ := json.MarshalIndent(d, "", "  ")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return nil, err
	}
	return keys, nil
}

// generate creates a fresh Ed25519 + X25519 keypair.
func generate() (*Keys, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var sealPriv [32]byte
	if _, err := rand.Read(sealPriv[:]); err != nil {
		return nil, err
	}
	sealPubSlice, err := curve25519.X25519(sealPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	k := &Keys{SignPub: pub, SignPriv: priv}
	copy(k.SealPriv[:], sealPriv[:])
	copy(k.SealPub[:], sealPubSlice)
	return k, nil
}

// fromDisk reconstructs the full keypair (recomputing the public halves) from stored privates.
func fromDisk(d onDisk) (*Keys, error) {
	signPriv, err := base64.StdEncoding.DecodeString(d.SignPriv)
	if err != nil {
		return nil, err
	}
	sealPrivBytes, err := base64.StdEncoding.DecodeString(d.SealPriv)
	if err != nil {
		return nil, err
	}
	k := &Keys{
		SignPriv: ed25519.PrivateKey(signPriv),
		SignPub:  ed25519.PrivateKey(signPriv).Public().(ed25519.PublicKey),
	}
	copy(k.SealPriv[:], sealPrivBytes)
	sealPub, err := curve25519.X25519(k.SealPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(k.SealPub[:], sealPub)
	return k, nil
}

// SigningPublicB64 is the base64 Ed25519 public key registered with cloud at enrollment.
func (k *Keys) SigningPublicB64() string {
	return base64.StdEncoding.EncodeToString(k.SignPub)
}

// SealingPublicB64 is the base64 X25519 public key operators seal secrets to.
func (k *Keys) SealingPublicB64() string {
	return base64.StdEncoding.EncodeToString(k.SealPub[:])
}

// Sign produces a detached Ed25519 signature over msg.
func (k *Keys) Sign(msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.SignPriv, msg))
}
