// Package secrets generates and persists the deployment's MACHINE secrets on the VM.
//
// These values are created here, by the agent, and never travel to cloud: DB passwords,
// the app crypto secrets (JWT/HMAC/COOKIE), the Redis password, and the Gitea admin
// bootstrap credentials. Cloud stores config + sealed human secrets only — never these.
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
	PostgresSuperPassword string `json:"postgresSuperPassword"`
	DBOwnerPassword       string `json:"dbOwnerPassword"`
	DBAppPassword         string `json:"dbAppPassword"`
	JWTSecret             string `json:"jwtSecret"`
	HMACKey               string `json:"hmacKey"`
	CookieSecret          string `json:"cookieSecret"`
	RedisPassword         string `json:"redisPassword"`
	GiteaAdminUser        string `json:"giteaAdminUser"`
	GiteaAdminPassword    string `json:"giteaAdminPassword"`
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
		PostgresSuperPassword: randHex(24),
		DBOwnerPassword:       randHex(24),
		DBAppPassword:         randHex(24),
		JWTSecret:             randB64(32),
		HMACKey:               randB64(32),
		CookieSecret:          randB64(32),
		RedisPassword:         randHex(24),
		GiteaAdminUser:        "vritti-admin",
		GiteaAdminPassword:    randHex(24),
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
