// Package gitea handles the agent side of the Gitea add-on: after the agent starts the Gitea
// container, it bootstraps an admin + a one-shot admin API token. That token is handed to
// core-server (via env), and core — not the agent — creates the app git user + PAT and stores
// both in vritti_core. The agent persists the admin token locally so provisioning is idempotent.
package gitea

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secrets"
)

// state is the persisted admin token so we never regenerate (Gitea rejects duplicate token names).
type state struct {
	AdminToken string `json:"adminToken"`
}

const containerName = "gitea"
const tokenName = "vritti-agent-bootstrap"

// ProvisionAdminToken ensures a Gitea admin exists and returns a stable admin API token.
func ProvisionAdminToken(ctx context.Context, dx *dockerx.Client, m *secrets.Machine, stateDir string) (string, error) {
	statePath := filepath.Join(stateDir, "gitea-state.json")
	if data, err := os.ReadFile(statePath); err == nil {
		var s state
		if json.Unmarshal(data, &s) == nil && s.AdminToken != "" {
			return s.AdminToken, nil
		}
	}

	if err := ensureAdmin(ctx, dx, m); err != nil {
		return "", err
	}
	token, err := generateToken(ctx, dx, m)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	blob, _ := json.Marshal(state{AdminToken: token})
	if err := os.WriteFile(statePath, blob, 0o600); err != nil {
		return "", err
	}
	return token, nil
}

// ensureAdmin creates the admin user, treating "already exists" as success.
func ensureAdmin(ctx context.Context, dx *dockerx.Client, m *secrets.Machine) error {
	cmd := giteaCLI(fmt.Sprintf(
		"gitea admin user create --admin --username %s --password %s --email %s@vritti.local --must-change-password=false",
		m.GiteaAdminUser, m.GiteaAdminPassword, m.GiteaAdminUser,
	))
	code, out, err := dx.Exec(ctx, containerName, cmd)
	if err != nil {
		return err
	}
	if code != 0 && !strings.Contains(strings.ToLower(out), "already exist") {
		return fmt.Errorf("gitea admin create failed (exit %d): %s", code, out)
	}
	return nil
}

// generateToken mints an all-scopes admin token and returns the raw value.
func generateToken(ctx context.Context, dx *dockerx.Client, m *secrets.Machine) (string, error) {
	cmd := giteaCLI(fmt.Sprintf(
		"gitea admin user generate-access-token --username %s --scopes all --token-name %s --raw",
		m.GiteaAdminUser, tokenName,
	))
	code, out, err := dx.Exec(ctx, containerName, cmd)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("gitea token generation failed (exit %d): %s", code, out)
	}
	// --raw prints only the token; guard against any trailing log noise.
	token := strings.TrimSpace(lastLine(out))
	if token == "" {
		return "", fmt.Errorf("gitea returned an empty token")
	}
	return token, nil
}

// giteaCLI runs a gitea command inside the container as the git user with the right work dir.
func giteaCLI(command string) []string {
	return []string{"su", "git", "-c", "GITEA_WORK_DIR=/data/gitea " + command}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
