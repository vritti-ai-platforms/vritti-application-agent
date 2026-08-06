// Package gitea handles the agent side of the Gitea add-on: after the agent starts the Gitea
// container, it bootstraps an admin + a one-shot admin API token. That token is handed to
// core-server (via env), and core — not the agent — creates the app git user + PAT and stores
// both in vritti_core. The agent persists the admin token locally so provisioning is idempotent.
package gitea

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// state is the persisted admin token so we never regenerate (Gitea rejects duplicate token names).
type state struct {
	AdminToken string `json:"adminToken"`
}

const containerName = "gitea"
const tokenName = "vritti-agent-bootstrap"

// giteaInternalURL is the Gitea HTTP API on the shared stack network (the agent joins vritti-core-net).
const giteaInternalURL = "http://" + containerName + ":3000"

// ProvisionAdminToken ensures a Gitea admin exists and returns a stable admin API token. The admin
// bootstrap creds come from Infisical's `/agent` folder (never generated).
func ProvisionAdminToken(ctx context.Context, dx *dockerx.Client, adminUser, adminPassword, stateDir string) (string, error) {
	statePath := filepath.Join(stateDir, "gitea-state.json")
	if data, err := os.ReadFile(statePath); err == nil {
		var s state
		if json.Unmarshal(data, &s) == nil && s.AdminToken != "" {
			return s.AdminToken, nil
		}
	}

	if err := ensureAdmin(ctx, dx, adminUser, adminPassword); err != nil {
		return "", err
	}
	token, err := generateToken(ctx, dx, adminUser, adminPassword)
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
func ensureAdmin(ctx context.Context, dx *dockerx.Client, adminUser, adminPassword string) error {
	cmd := giteaCLI(fmt.Sprintf(
		"gitea admin user create --admin --username %s --password %s --email %s@vritti.local --must-change-password=false",
		adminUser, adminPassword, adminUser,
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

// generateToken mints an all-scopes admin token and returns the raw value. It first deletes any token of
// the same name so it's idempotent: Gitea rejects a duplicate token name and won't hand back an existing
// secret, so if our cached copy is gone (e.g. the agent state dir was wiped on re-enroll while Gitea's
// volume kept the token) a plain generate loops forever on "name has been used already".
func generateToken(ctx context.Context, dx *dockerx.Client, adminUser, adminPassword string) (string, error) {
	if err := deleteExistingToken(ctx, adminUser, adminPassword); err != nil {
		return "", err
	}
	cmd := giteaCLI(fmt.Sprintf(
		"gitea admin user generate-access-token --username %s --scopes all --token-name %s --raw",
		adminUser, tokenName,
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

// deleteExistingToken removes any admin token named tokenName via the Gitea API (basic auth with the admin
// creds), so the subsequent generate never collides. 404 (no such token) is treated as success.
func deleteExistingToken(ctx context.Context, adminUser, adminPassword string) error {
	url := fmt.Sprintf("%s/api/v1/users/%s/tokens/%s", giteaInternalURL, adminUser, tokenName)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(adminUser, adminPassword)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("gitea token delete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("gitea token delete failed (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// giteaCLI runs a gitea command inside the container as the git user with the right work dir.
func giteaCLI(command string) []string {
	return []string{"su", "git", "-c", "GITEA_WORK_DIR=/data/gitea " + command}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
