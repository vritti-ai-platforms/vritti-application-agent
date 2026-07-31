// Package config loads the agent's own runtime configuration. This is the ONLY
// human-supplied input the agent needs to bootstrap: where cloud is, which deployment
// it serves, and the one-time enrollment token shown once in the admin UI.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config is the agent's boot configuration.
type Config struct {
	CloudURL     string        // e.g. https://cloud.vrittiai.com
	DeploymentID string        // the deployment this agent serves
	EnrollToken  string        // one-time token from admin (burned after first enroll)
	DataDir      string        // agent state root (keys, secrets, enrollment)
	StackRoot    string        // host path for bind mounts (/opt/vritti-core)
	PollInterval time.Duration // desired-state poll cadence

	// Data-store passwords — supplied via the agent's env file or Infisical (agent folder), never
	// generated, so they are centrally managed. Required for managed mode (used to init Postgres +
	// Redis and create the owner/app/gitea roles); ignored in external mode.
	PostgresSuperPassword string
	DBOwnerPassword       string
	DBAppPassword         string
	DBGiteaPassword       string
	RedisPassword         string
	GiteaAdminUser        string // Gitea admin bootstrap credentials — user-provided, not generated
	GiteaAdminPassword    string

	// Cloudflare Access service token — cloud's agent API sits behind the Access-gated admin
	// surface, so every request must carry these as CF-Access-Client-Id/Secret headers. Sourced
	// from env or the Infisical agent folder (same as the data-store creds).
	CFAccessClientID     string
	CFAccessClientSecret string
}

// Load reads configuration from the environment, applying sane defaults.
func Load() (*Config, error) {
	c := &Config{
		CloudURL:     os.Getenv("VRITTI_CLOUD_URL"),
		DeploymentID: os.Getenv("VRITTI_DEPLOYMENT_ID"),
		EnrollToken:  os.Getenv("VRITTI_ENROLL_TOKEN"),
		DataDir:      envOr("VRITTI_DATA_DIR", "/var/lib/vritti-agent"),
		StackRoot:    envOr("VRITTI_STACK_ROOT", "/opt/vritti-core"),
		PollInterval: 20 * time.Second,

		PostgresSuperPassword: os.Getenv("VRITTI_POSTGRES_SUPER_PASSWORD"),
		DBOwnerPassword:       os.Getenv("VRITTI_DB_OWNER_PASSWORD"),
		DBAppPassword:         os.Getenv("VRITTI_DB_APP_PASSWORD"),
		DBGiteaPassword:       os.Getenv("VRITTI_DB_GITEA_PASSWORD"),
		RedisPassword:         os.Getenv("VRITTI_REDIS_PASSWORD"),
		GiteaAdminUser:        os.Getenv("VRITTI_GITEA_ADMIN_USER"),
		GiteaAdminPassword:    os.Getenv("VRITTI_GITEA_ADMIN_PASSWORD"),

		CFAccessClientID:     os.Getenv("VRITTI_CF_ACCESS_CLIENT_ID"),
		CFAccessClientSecret: os.Getenv("VRITTI_CF_ACCESS_CLIENT_SECRET"),
	}
	if c.CloudURL == "" {
		return nil, fmt.Errorf("VRITTI_CLOUD_URL is required")
	}
	if c.DeploymentID == "" {
		return nil, fmt.Errorf("VRITTI_DEPLOYMENT_ID is required")
	}
	// Fill any data-store secret still empty from the deployment's Infisical agent folder.
	if err := fillFromInfisical(c); err != nil {
		return nil, err
	}
	return c, nil
}

// KeysDir is where the agent's local keypairs live.
func (c *Config) KeysDir() string { return filepath.Join(c.DataDir, "keys") }

// SecretsDir is where agent-generated machine secrets are persisted.
func (c *Config) SecretsDir() string { return filepath.Join(c.DataDir, "secrets") }

// EnrollmentPath is where the completed-enrollment record (deployment pubkey, credential) is cached.
func (c *Config) EnrollmentPath() string { return filepath.Join(c.DataDir, "enrollment.json") }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
