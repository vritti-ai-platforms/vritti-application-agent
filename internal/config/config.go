// Package config loads the agent's own runtime configuration. This is the ONLY human-supplied
// input the agent needs to bootstrap: where cloud is, which deployment it serves, and the one-time
// enrollment token shown once in the admin UI. Everything store-specific (the secret provider's
// connection + auth) arrives later in the cloud-signed desired-state, not here.
package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config is the agent's boot configuration.
type Config struct {
	CloudAPIURL  string // agent API base, e.g. https://api.vrittiai.com
	DeploymentID string // the deployment this agent serves
	EnrollToken  string // one-time token from admin (burned after first enroll)
	DataDir      string // agent state root (keys, secrets, enrollment)
	StackRoot    string // host path for bind mounts (/opt/vritti-core)
}

// Load reads configuration from the environment, applying sane defaults.
func Load() (*Config, error) {
	c := &Config{
		CloudAPIURL:  os.Getenv("VRITTI_CLOUD_API_URL"),
		DeploymentID: os.Getenv("VRITTI_DEPLOYMENT_ID"),
		EnrollToken:  os.Getenv("VRITTI_ENROLL_TOKEN"),
		DataDir:      envOr("VRITTI_DATA_DIR", "/var/lib/vritti-agent"),
		StackRoot:    envOr("VRITTI_STACK_ROOT", "/opt/vritti-core"),
	}
	if c.CloudAPIURL == "" {
		return nil, fmt.Errorf("VRITTI_CLOUD_API_URL is required")
	}
	if c.DeploymentID == "" {
		return nil, fmt.Errorf("VRITTI_DEPLOYMENT_ID is required")
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
