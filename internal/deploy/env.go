package deploy

import (
	"fmt"
	"sort"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secrets"
)

// CoreEnvInput is everything needed to render core-server's environment.
type CoreEnvInput struct {
	Desired          cloudapi.DesiredState
	Machine          *secrets.Machine
	DB               DBConn
	RedisPassword    string            // → REDIS_URL (config-supplied, not machine-generated)
	ResolvedConfig   map[string]string // plaintext config + decrypted sealed secrets (incl. LICENSE_PUBLIC_KEY, R2, etc.)
	GiteaURL         string            // set when the Gitea add-on is provisioned
	GiteaAdminToken  string            // bootstrap admin token handed to core so it can create the app user+PAT
}

// RenderCoreEnv builds the env slice for the core-server container.
func RenderCoreEnv(in CoreEnvInput) []string {
	env := baseAppEnv(in.DB, in.Machine)
	env["NODE_ENV"] = "production"
	env["PORT"] = "3002"
	env["DEPLOYMENT_ID"] = in.Desired.DeploymentID
	env["BASE_DOMAIN"] = in.Desired.BaseDomain
	env["JWT_SECRET"] = in.Machine.JWTSecret
	env["HMAC_KEY"] = in.Machine.HMACKey
	env["COOKIE_SECRET"] = in.Machine.CookieSecret
	env["REDIS_URL"] = fmt.Sprintf("redis://:%s@%s:6379", in.RedisPassword, SvcRedis)
	env["NATS_URL"] = fmt.Sprintf("nats://%s:4222", SvcNats)

	if in.GiteaURL != "" {
		// core-server creates the app git user + PAT via this admin token, then stores them in vritti_core.
		env["GITEA_BASE_URL"] = in.GiteaURL
		env["GITEA_ADMIN_TOKEN"] = in.GiteaAdminToken
	}

	// Plaintext config + decrypted human secrets (R2 keys/buckets, tunables) pass through as-is.
	for k, v := range in.ResolvedConfig {
		env[k] = v
	}
	return toSlice(env)
}

// RenderServiceEnv builds the env slice for the commerce-service microservice.
func RenderServiceEnv(ds cloudapi.DesiredState, m *secrets.Machine, db DBConn, resolved map[string]string) []string {
	env := baseAppEnv(db, m)
	env["NODE_ENV"] = "production"
	env["APP_NAME"] = "commerce-service"
	env["NATS_URL"] = fmt.Sprintf("nats://%s:4222", SvcNats)
	env["DEPLOYMENT_ID"] = ds.DeploymentID
	for k, v := range resolved {
		env[k] = v
	}
	return toSlice(env)
}

// baseAppEnv is the shared DB connection block used by both node services.
func baseAppEnv(db DBConn, m *secrets.Machine) map[string]string {
	return map[string]string{
		"PRIMARY_DB_HOST":     db.Host,
		"PRIMARY_DB_PORT":     db.Port,
		"PRIMARY_DB_DATABASE": db.Database,
		"PRIMARY_DB_USERNAME": db.AppUser,
		"PRIMARY_DB_PASSWORD": db.AppPassword,
		"PRIMARY_DB_SSL_MODE": db.SSLMode,
		// Owner connection used only by the one-shot migrate runner (migrations + grants).
		"DATABASE_DIRECT_URL": db.DirectURL(),
	}
}

// toSlice converts a map into a deterministic KEY=VALUE slice (sorted for stable spec hashes).
func toSlice(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}
