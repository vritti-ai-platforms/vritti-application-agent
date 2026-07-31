// Infisical secret source for the agent's data-store credentials. When configured, the agent
// pulls the Postgres/Redis/Gitea passwords from a self-hosted Infisical folder (the deployment's
// `agent` folder, e.g. apw1 /agent) instead of requiring them all as env. These are the only
// secrets the agent SOURCES (machine crypto secrets are still generated locally); cloud never
// sees them. Env values always win — Infisical only fills gaps.
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// infisicalSource locates the deployment's secret folder and the machine identity to read it.
type infisicalSource struct {
	URL          string // self-hosted base, e.g. https://infisical.vrittiai.com
	ClientID     string // universal-auth machine identity
	ClientSecret string
	ProjectID    string // workspace id (vritti-core project)
	Env          string // e.g. apw1
	Path         string // e.g. /agent
}

// infisicalSecretKeys maps Infisical secret names in the agent folder to the config field they
// fill. Values are applied only where the field is still empty, so env (VRITTI_*) always wins.
var infisicalSecretKeys = map[string]func(*Config) *string{
	"POSTGRES_SUPER_PASSWORD": func(c *Config) *string { return &c.PostgresSuperPassword },
	"DB_OWNER_PASSWORD":       func(c *Config) *string { return &c.DBOwnerPassword },
	"DB_APP_PASSWORD":         func(c *Config) *string { return &c.DBAppPassword },
	"DB_GITEA_PASSWORD":       func(c *Config) *string { return &c.DBGiteaPassword },
	"REDIS_PASSWORD":          func(c *Config) *string { return &c.RedisPassword },
	"GITEA_ADMIN_USER":        func(c *Config) *string { return &c.GiteaAdminUser },
	"GITEA_ADMIN_PASSWORD":    func(c *Config) *string { return &c.GiteaAdminPassword },
	"CF_ACCESS_CLIENT_ID":     func(c *Config) *string { return &c.CFAccessClientID },
	"CF_ACCESS_CLIENT_SECRET": func(c *Config) *string { return &c.CFAccessClientSecret },
}

// infisicalFromEnv reads the machine-identity + folder location from VRITTI_INFISICAL_* env.
func infisicalFromEnv() infisicalSource {
	return infisicalSource{
		URL:          strings.TrimRight(envOr("VRITTI_INFISICAL_URL", "https://infisical.vrittiai.com"), "/"),
		ClientID:     envOr("VRITTI_INFISICAL_CLIENT_ID", ""),
		ClientSecret: envOr("VRITTI_INFISICAL_CLIENT_SECRET", ""),
		ProjectID:    envOr("VRITTI_INFISICAL_PROJECT_ID", ""),
		Env:          envOr("VRITTI_INFISICAL_ENV", ""),
		Path:         envOr("VRITTI_INFISICAL_PATH", "/agent"),
	}
}

// enabled reports whether enough is configured to authenticate and fetch.
func (s infisicalSource) enabled() bool {
	return s.URL != "" && s.ClientID != "" && s.ClientSecret != "" && s.ProjectID != "" && s.Env != ""
}

// fillFromInfisical fetches the agent folder's secrets and fills any config field still empty.
// It is a no-op (and never fatal) when the source is not configured; managed-mode validation
// happens later in the deploy path, so a partial fetch just surfaces there.
func fillFromInfisical(c *Config) error {
	src := infisicalFromEnv()
	if !src.enabled() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	secrets, err := src.fetch(ctx)
	if err != nil {
		return fmt.Errorf("infisical fetch (%s %s): %w", src.Env, src.Path, err)
	}
	for key, field := range infisicalSecretKeys {
		v, ok := secrets[key]
		if !ok || v == "" {
			continue
		}
		if p := field(c); *p == "" { // env-first: fill only what env left empty
			*p = v
		}
	}
	return nil
}

// login exchanges the machine identity for a short-lived access token (universal auth).
func (s infisicalSource) login(ctx context.Context) (string, error) {
	body, _ := json.Marshal(map[string]string{"clientId": s.ClientID, "clientSecret": s.ClientSecret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL+"/api/v1/auth/universal-auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	s.decorate(req)
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := do(req, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}
	return out.AccessToken, nil
}

// fetch logs in and returns key→value for the folder (with shared imports expanded).
func (s infisicalSource) fetch(ctx context.Context) (map[string]string, error) {
	token, err := s.login(ctx)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("workspaceId", s.ProjectID)
	q.Set("environment", s.Env)
	q.Set("secretPath", s.Path)
	q.Set("expandSecretReferences", "true")
	q.Set("include_imports", "true")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+"/api/v3/secrets/raw?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	s.decorate(req)
	req.Header.Set("Authorization", "Bearer "+token)

	var out struct {
		Secrets []struct {
			SecretKey   string `json:"secretKey"`
			SecretValue string `json:"secretValue"`
		} `json:"secrets"`
		Imports []struct {
			Secrets []struct {
				SecretKey   string `json:"secretKey"`
				SecretValue string `json:"secretValue"`
			} `json:"secrets"`
		} `json:"imports"`
	}
	if err := do(req, &out); err != nil {
		return nil, err
	}
	// Folder secrets take precedence over imported (shared) ones, so apply imports first.
	merged := map[string]string{}
	for _, imp := range out.Imports {
		for _, kv := range imp.Secrets {
			merged[kv.SecretKey] = kv.SecretValue
		}
	}
	for _, kv := range out.Secrets {
		merged[kv.SecretKey] = kv.SecretValue
	}
	return merged, nil
}

// decorate sets the JSON + a non-default User-Agent (the self-hosted Infisical sits behind
// Cloudflare, which 1010-blocks known bot UAs like Go's default).
func (s infisicalSource) decorate(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vritti-application-agent")
}

// do issues the request and decodes a 2xx JSON body into out.
func do(req *http.Request, out any) error {
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %d %s", req.URL.Path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return json.Unmarshal(b, out)
}
