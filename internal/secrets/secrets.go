// Package secrets generates and persists the deployment's MACHINE secrets on the VM.
//
// In Model B the app crypto secrets (JWT/HMAC/COOKIE/ENCRYPTION) come from Infisical's
// `/core-server` env — the agent no longer generates them. The only value still minted here is
// the pgBackRest cipher passphrase, which encrypts backups locally and must never leave the VM.
package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// Machine is the set of locally generated secrets, persisted once and reused across reconciles.
type Machine struct {
	PgBackRestCipherPass string `json:"pgBackRestCipherPass"`
}

// LoadOrCreate returns the persisted machine secrets, generating them on first run.
func LoadOrCreate(dir string) (*Machine, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "machine.json")

	if data, err := os.ReadFile(path); err == nil {
		var m Machine
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		return &m, nil
	}

	m := &Machine{
		PgBackRestCipherPass: randHex(32),
	}
	blob, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return nil, err
	}
	return m, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
