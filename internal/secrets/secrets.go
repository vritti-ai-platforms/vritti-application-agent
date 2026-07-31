// Package secrets generates and persists the deployment's MACHINE secrets on the VM.
//
// These values are created here, by the agent, and never travel to cloud: the app crypto
// secrets (JWT/HMAC/COOKIE) and the pgBackRest cipher pass. Cloud stores config + sealed human
// secrets only — never these. Data-store passwords (Postgres + Redis) and the Gitea admin
// password are NOT here: they are supplied via config (env file / Infisical agent folder).
package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// Machine is the set of locally generated secrets, persisted once and reused across reconciles.
type Machine struct {
	JWTSecret            string `json:"jwtSecret"`
	HMACKey              string `json:"hmacKey"`
	CookieSecret         string `json:"cookieSecret"`
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
		JWTSecret:            randB64(32),
		HMACKey:              randB64(32),
		CookieSecret:         randB64(32),
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

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
