// Package agent is the top-level orchestration loop. It wires the pieces together and, on
// every desired-state generation, sequences the deterministic reconcile:
//
//	verify signature → fetch each service's env from the secret provider → derive provisioning creds →
//	resolve DB (mode branch) → ensure infra → provision managed DB → run migrations →
//	reconcile services → provision Gitea add-on → prune stragglers → report status.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/agentcrypto"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/config"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/deploy"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/enroll"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/gitea"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secretprovider"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secrets"
)

// Version is the agent build version reported to cloud at enrollment.
const Version = "0.1.0"

// externalDBSecret is the reserved sealed-secret name carrying the external DB connection.
const externalDBSecret = "external_db"

// secretProviderPrefix marks sealed secrets that carry the SECRET half of the secret-store auth
// method. The suffix after the prefix is the reserved auth-secret name (clientSecret, token, ...).
const secretProviderPrefix = "secretProvider."

// Agent holds the long-lived collaborators for one deployment.
type Agent struct {
	cfg        *config.Config
	log        *slog.Logger
	keys       *agentcrypto.Keys
	machine    *secrets.Machine
	dx         *dockerx.Client
	cloud      *cloudapi.Client
	enrollment *cloudapi.Enrollment

	lastGeneration int64
	archiving      bool                  // pgBackRest add-on currently enabled (drives the backup ticker)
	hadFullBackup  bool                  // a full backup has been taken since archiving was enabled
	edgeManaged    bool                  // agent runs nginx + the bundled acme-dns wildcard edge
	certs          []cloudapi.CertReport // last observed managed-edge certs (reported each heartbeat)
	// acmeDelegation, when set, is the one-time CNAME the operator must add before the wildcard cert
	// can issue — surfaced in the heartbeat for the wizard's DNS-Delegation step.
	acmeDelegation *cloudapi.AcmeChallengeDelegation
}

// New bootstraps the agent: loads config, local keys, machine secrets, and the Docker client.
func New(ctx context.Context, log *slog.Logger) (*Agent, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	keys, err := agentcrypto.LoadOrCreate(cfg.KeysDir())
	if err != nil {
		return nil, err
	}
	machine, err := secrets.LoadOrCreate(cfg.SecretsDir())
	if err != nil {
		return nil, err
	}
	dx, err := dockerx.New(cfg.DeploymentID)
	if err != nil {
		return nil, err
	}
	cloud := cloudapi.New(cfg.CloudAPIURL, cfg.DeploymentID, keys)

	return &Agent{cfg: cfg, log: log, keys: keys, machine: machine, dx: dx, cloud: cloud}, nil
}

// Run enrolls (once) then loops: poll desired-state, reconcile, report — until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	enr, err := enroll.Run(ctx, a.cloud, a.keys, a.cfg, Version)
	if err != nil {
		return err
	}
	a.enrollment = enr
	a.cloud.SetCredential(enr.AgentCredential)
	a.log.Info("enrolled", "deployment", a.cfg.DeploymentID)

	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()

	// Backup schedule (only fires when the pgBackRest add-on is enabled): hourly incremental,
	// with a full every 24th tick (daily). The initial full is taken at enable time in reconcile.
	backupTicker := time.NewTicker(time.Hour)
	defer backupTicker.Stop()
	backupTick := 0

	// Wildcard cert renewal is handled inside each reconcile (EnsureEdge reissues via lego once the
	// cert is within its renewal window) — no separate ticker needed.

	a.tick(ctx) // reconcile immediately on boot
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			a.tick(ctx)
		case <-backupTicker.C:
			if a.archiving {
				backupTick++
				bt := "incr"
				if backupTick%24 == 0 {
					bt = "full"
				}
				if err := deploy.RunBackup(ctx, a.dx, bt); err != nil {
					a.log.Warn("scheduled backup failed", "type", bt, "err", err)
				} else {
					a.log.Info("scheduled backup complete", "type", bt)
				}
			}
		}
	}
}

// tick fetches the current desired-state, authenticates it, and reconciles once, reporting the outcome.
func (a *Agent) tick(ctx context.Context) {
	signed, err := a.cloud.FetchDesiredState(ctx)
	if err != nil {
		a.log.Warn("fetch desired-state failed", "err", err)
		return
	}

	ds, err := a.verifyDesiredState(signed)
	if err != nil {
		a.log.Error("reject desired-state", "err", err)
		a.report(ctx, 0, "error", err.Error(), false)
		return
	}

	giteaOK, err := a.reconcile(ctx, ds)
	phase, msg := "ready", ""
	switch {
	case err != nil:
		phase, msg = "error", err.Error()
		a.log.Error("reconcile failed", "err", err)
	case a.acmeDelegation != nil:
		// Cert-first gate: the stack is held until the operator's DNS lands and the wildcard issues.
		phase, msg = "awaiting-dns", "Waiting for the DNS delegation before provisioning the stack."
	}
	a.report(ctx, ds.Generation, phase, msg, giteaOK)
}

// verifyDesiredState authenticates the signed desired-state and returns the payload decoded from
// EXACTLY the verified bytes — there is no separately-transmitted object to act on by mistake.
func (a *Agent) verifyDesiredState(signed *cloudapi.SignedDesiredState) (cloudapi.DesiredState, error) {
	if !agentcrypto.VerifyDeployment(a.enrollment.DeploymentPubKey, []byte(signed.PayloadB64), signed.Signature) {
		return cloudapi.DesiredState{}, fmt.Errorf("signature did not verify — refusing to apply")
	}
	var ds cloudapi.DesiredState
	if err := json.Unmarshal([]byte(signed.PayloadB64), &ds); err != nil {
		return cloudapi.DesiredState{}, fmt.Errorf("decode signed desired-state: %w", err)
	}
	return ds, nil
}

// reconcile drives the stack toward one already-verified desired-state. Returns whether Gitea is provisioned.
func (a *Agent) reconcile(ctx context.Context, ds cloudapi.DesiredState) (bool, error) {
	// (2) Decrypt the sealed secrets once. Names prefixed `secretProvider.` carry the SECRET half of
	// the secret-store auth method (client secret, token, jwt, ...) — strip the prefix into
	// authSecrets. The reserved `external_db` name carries the external-mode DB connection.
	authSecrets := map[string]string{}
	var externalSecret []byte
	for name, ciphertext := range ds.SealedSecrets {
		plain, err := a.keys.OpenSealed(ciphertext)
		if err != nil {
			return false, fmt.Errorf("open sealed secret %q: %w", name, err)
		}
		switch {
		case strings.HasPrefix(name, secretProviderPrefix):
			authSecrets[strings.TrimPrefix(name, secretProviderPrefix)] = string(plain)
		case name == externalDBSecret:
			externalSecret = plain
		}
	}

	// (3) Build the secret provider from the cloud-signed desired-state (connection + auth method come
	// from cloud, never from env/ansible), then read each service's COMPLETE container env through it
	// (imports merged, refs expanded). coreEnv/commerceEnv ARE the container envs; agentEnv holds only
	// the raw provisioning creds (data-store passwords + Gitea admin bootstrap) to stand up the infra.
	if ds.SecretProvider == nil {
		return false, fmt.Errorf("desired-state has no secretProvider — Model B requires a cloud-configured secret store")
	}
	provider, err := secretprovider.New(ctx, *ds.SecretProvider, authSecrets)
	if err != nil {
		return false, fmt.Errorf("secret provider: %w", err)
	}
	coreEnv, err := provider.Fetch(ctx, "/core-server")
	if err != nil {
		return false, fmt.Errorf("secrets /core-server: %w", err)
	}
	commerceEnv, err := provider.Fetch(ctx, "/commerce-service")
	if err != nil {
		return false, fmt.Errorf("secrets /commerce-service: %w", err)
	}
	agentEnv, err := provider.Fetch(ctx, "/agent")
	if err != nil {
		return false, fmt.Errorf("secrets /agent: %w", err)
	}

	// (4) Derive the managed-mode provisioning values + Gitea admin creds from the `/agent` map.
	prov := deploy.ManagedProvisioning{
		DBName:        agentEnv["DB_NAME"],
		OwnerPassword: agentEnv["DB_OWNER_PASSWORD"],
		AppPassword:   agentEnv["DB_APP_PASSWORD"],
		GiteaPassword: agentEnv["DB_GITEA_PASSWORD"],
		RedisPassword: agentEnv["REDIS_PASSWORD"],
	}
	giteaAdminUser := agentEnv["GITEA_ADMIN_USER"]
	giteaAdminPw := agentEnv["GITEA_ADMIN_PASSWORD"]

	// (5) Resolve the DB connection — the mode branch (managed = provisioning creds, external = sealed).
	db, err := deploy.ResolveDBConn(ds, prov, externalSecret)
	if err != nil {
		return false, err
	}

	// (6) Ensure infra: network + host bind directories.
	if err := a.dx.EnsureNetwork(ctx, deploy.Network); err != nil {
		return false, err
	}
	for _, dir := range deploy.Dirs(a.cfg.StackRoot, ds) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return false, err
		}
	}
	// The core-server / commerce-service containers run as uid 1001 (nestjs) and write to their
	// bind-mounted /app/logs — hand the host log dir to that uid, else the app boots then crashes with
	// "EACCES: permission denied, open 'logs/…'". Applies in both DB modes (the app always logs).
	if err := os.Chown(deploy.CoreLogDir(a.cfg.StackRoot), deploy.CoreServerUID, deploy.CoreServerUID); err != nil {
		return false, fmt.Errorf("chown core log dir: %w", err)
	}
	// MkdirAll creates the pgdata dir owned by the (root) agent, but the postgres container runs as
	// uid 999 and must be able to write its bind-mounted data dir — hand ownership over, else initdb
	// fails with "mkdir: cannot create directory '/var/lib/postgresql/data': Permission denied".
	if ds.Mode == cloudapi.ModeManaged {
		if err := os.Chown(deploy.PostgresDataDir(a.cfg.StackRoot), deploy.PostgresUID, deploy.PostgresUID); err != nil {
			return false, fmt.Errorf("chown postgres data dir: %w", err)
		}
	}

	keep := map[string]bool{}

	// (6.5) Managed edge, CERT-FIRST: bring up acme-dns and issue the single *.<base> wildcard BEFORE
	// provisioning, and GATE the stack on it. This means the app containers never start until the
	// operator's DNS is in place and the cert exists — no point serving nothing over TLS. edge=external
	// skips this (a BYO ingress/LB fronts core, so the agent runs no nginx/acme-dns).
	a.edgeManaged = ds.Edge != cloudapi.EdgeExternal && ds.BaseDomain != ""
	if a.edgeManaged {
		delegation, issued, certs, err := deploy.EnsureWildcard(ctx, a.dx, ds, a.cfg.StackRoot)
		if err != nil {
			return false, err
		}
		a.acmeDelegation = delegation
		a.certs = certs
		keep[deploy.SvcAcmeDns] = true
		if !issued {
			// Waiting on the operator's DNS (zone delegation + CNAME). Keep acme-dns running and retry
			// next tick; do NOT provision the app stack until the wildcard is in place.
			return false, nil
		}
	} else {
		a.acmeDelegation = nil
		a.certs = nil
	}

	// (7) Managed mode: bring up Postgres (archive-aware), wait healthy, provision roles/schemas,
	// and — when the pgBackRest add-on is on — write its config, init the stanza, take a base backup.
	archiving := ds.Mode == cloudapi.ModeManaged && ds.AddOns.PgBackRest
	if ds.Mode == cloudapi.ModeManaged {
		if archiving {
			// Config must exist before Postgres boots so archive_command works from the first WAL.
			// R2 repo creds ride in core-server's env map (R2_*), so read the backup target from there.
			conf := deploy.RenderPgBackRestConf(ds, a.machine, coreEnv)
			confPath := filepath.Join(a.cfg.StackRoot, "pgbackrest", "pgbackrest.conf")
			if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
				return false, err
			}
		}
		pg := deploy.PostgresSpec(ds, db, a.cfg.StackRoot, archiving)
		if err := deploy.Apply(ctx, a.dx, pg); err != nil {
			return false, fmt.Errorf("postgres: %w", err)
		}
		keep[pg.Name] = true
		if err := a.dx.WaitHealthy(ctx, deploy.SvcPostgres, 90*time.Second); err != nil {
			return false, err
		}
		if err := deploy.EnsureManagedDatabase(ctx, a.dx, db); err != nil {
			return false, err
		}
		if archiving {
			if err := deploy.EnsureStanza(ctx, a.dx); err != nil {
				return false, err
			}
			if !a.hadFullBackup {
				if err := deploy.RunBackup(ctx, a.dx, "full"); err != nil {
					return false, err
				}
				a.hadFullBackup = true
			}
		}
	}
	a.archiving = archiving

	// (8) Render the commerce env verbatim, then run migrations (owner conn) to completion before the
	// app services roll. core-migrate runs without the Gitea additions (they aren't needed for DDL).
	commerceEnvSlice := deploy.RenderServiceEnv(commerceEnv)
	if err := a.migrate(ctx, ds, deploy.RenderCoreEnv(coreEnv, "", ""), commerceEnvSlice); err != nil {
		return false, err
	}

	// (9) Reconcile the core long-running services.
	longRunning := []dockerx.RunSpec{
		deploy.RedisSpec(ds, prov.RedisPassword),
		deploy.NatsSpec(ds),
		deploy.CommerceServiceSpec(ds, commerceEnvSlice),
	}

	// (10) Gitea add-on: start it, then bootstrap the admin token BEFORE rendering core's env so
	// core boots already knowing GITEA_BASE_URL + GITEA_ADMIN_TOKEN and can create the app user + PAT.
	giteaProvisioned := false
	giteaURL, giteaToken := "", ""
	if ds.AddOns.Gitea {
		giteaSpec := deploy.GiteaSpec(ds, db, a.cfg.StackRoot)
		if err := deploy.Apply(ctx, a.dx, giteaSpec); err != nil {
			return false, fmt.Errorf("gitea: %w", err)
		}
		keep[giteaSpec.Name] = true
		if err := a.dx.WaitHealthy(ctx, deploy.SvcGitea, 90*time.Second); err != nil {
			return false, err
		}
		token, err := gitea.ProvisionAdminToken(ctx, a.dx, giteaAdminUser, giteaAdminPw, a.cfg.DataDir)
		if err != nil {
			return false, err
		}
		giteaURL = "http://" + deploy.SvcGitea + ":3000"
		giteaToken = token
		giteaProvisioned = true
	}

	// core-server rendered last so it carries the Gitea admin token when the add-on is on.
	coreEnvSlice := deploy.RenderCoreEnv(coreEnv, giteaURL, giteaToken)
	longRunning = append(longRunning, deploy.CoreServerSpec(ds, coreEnvSlice, a.cfg.StackRoot))

	for _, spec := range longRunning {
		if err := deploy.Apply(ctx, a.dx, spec); err != nil {
			return giteaProvisioned, fmt.Errorf("%s: %w", spec.Name, err)
		}
		keep[spec.Name] = true
	}

	// (11) Managed edge: the wildcard already exists (step 6.5) and the stack is now up, so render the
	// derived routes (api./git./*.) + sync the web bundles and (re)start nginx — it comes up serving
	// HTTPS immediately. edge=external means a BYO ingress/LB fronts core: no nginx, no acme-dns.
	if a.edgeManaged {
		certs, err := deploy.EnsureNginx(ctx, a.dx, ds, a.cfg.StackRoot, coreEnvSlice)
		if err != nil {
			return giteaProvisioned, err
		}
		a.certs = certs
		keep[deploy.SvcNginx] = true
		keep[deploy.SvcAcmeDns] = true
	}

	// (12) Prune anything we own that is no longer in the desired set (e.g. a disabled add-on).
	if err := a.dx.PruneExcept(ctx, keep); err != nil {
		return giteaProvisioned, err
	}

	a.lastGeneration = ds.Generation
	return giteaProvisioned, nil
}

// migrate runs the core + commerce one-shot migration containers to completion. Each runner reads
// its owner connection (PRIMARY_DB_DATABASE_DIRECT_URL) + app role (PRIMARY_DB_USERNAME) straight
// from its Infisical env map.
func (a *Agent) migrate(ctx context.Context, ds cloudapi.DesiredState, coreEnv, commerceEnv []string) error {
	runs := []struct {
		name  string
		image string
		env   []string
	}{
		{"core-migrate", ds.Images.CoreServer, coreEnv},
		{"commerce-migrate", ds.Images.CommerceService, commerceEnv},
	}
	for _, r := range runs {
		spec := deploy.MigrateSpec(r.name, r.image, r.env)
		if err := a.dx.PullImage(ctx, spec.Image); err != nil {
			return err
		}
		code, out, err := a.dx.RunToCompletion(ctx, spec)
		if err != nil {
			return fmt.Errorf("%s: %w", r.name, err)
		}
		if code != 0 {
			return fmt.Errorf("%s exited %d: %s", r.name, code, tailLog(out))
		}
		a.log.Info("migration complete", "runner", r.name)
	}
	return nil
}

// report pushes a heartbeat with per-service state; failures are logged, not fatal.
func (a *Agent) report(ctx context.Context, generation int64, phase, msg string, giteaOK bool) {
	statuses, _ := a.dx.List(ctx)
	containers := make([]cloudapi.ContainerReport, 0, len(statuses))
	for _, s := range statuses {
		cr := cloudapi.ContainerReport{Service: s.Service, Name: s.Name, State: s.State, Health: s.Health}
		if sample, err := a.dx.Stats(ctx, s.Name); err == nil {
			cr.CPUPercent = sample.CPUPercent
			cr.MemoryBytes = sample.MemoryBytes
		}
		containers = append(containers, cr)
	}
	err := a.cloud.ReportStatus(ctx, cloudapi.StatusReport{
		DeploymentID:     a.cfg.DeploymentID,
		Generation:       generation,
		Phase:            phase,
		Message:          msg,
		Containers:       containers,
		GiteaProvisioned: giteaOK,
		Certificates:     a.certs,
		AcmeDelegation:   a.acmeDelegation,
	})
	if err != nil {
		a.log.Warn("status report failed", "err", err)
	}
}

// tailLog trims migration output to a readable tail for error messages.
func tailLog(s string) string {
	if len(s) > 2000 {
		return "…" + s[len(s)-2000:]
	}
	return s
}
