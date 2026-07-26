// Package agent is the top-level orchestration loop. It wires the pieces together and, on
// every desired-state generation, sequences the deterministic reconcile:
//
//	verify signature → decrypt sealed secrets → resolve DB (mode branch) → ensure infra →
//	provision managed DB → run migrations → reconcile services → provision Gitea add-on →
//	prune stragglers → report status.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/agentcrypto"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/config"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/deploy"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/enroll"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/gitea"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secrets"
)

// Version is the agent build version reported to cloud at enrollment.
const Version = "0.1.0"

// externalDBSecret is the reserved sealed-secret name carrying the external DB connection.
const externalDBSecret = "external_db"

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
	archiving      bool // pgBackRest add-on currently enabled (drives the backup ticker)
	hadFullBackup  bool // a full backup has been taken since archiving was enabled
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
	cloud := cloudapi.New(cfg.CloudURL, cfg.DeploymentID, keys)

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

// tick fetches the current desired-state and reconciles once, reporting the outcome.
func (a *Agent) tick(ctx context.Context) {
	signed, err := a.cloud.FetchDesiredState(ctx)
	if err != nil {
		a.log.Warn("fetch desired-state failed", "err", err)
		return
	}

	giteaOK, err := a.reconcile(ctx, signed)
	phase, msg := "ready", ""
	if err != nil {
		phase, msg = "error", err.Error()
		a.log.Error("reconcile failed", "err", err)
	}
	a.report(ctx, signed.Payload.Generation, phase, msg, giteaOK)
}

// reconcile drives the stack toward one signed desired-state. Returns whether Gitea is provisioned.
func (a *Agent) reconcile(ctx context.Context, signed *cloudapi.SignedDesiredState) (bool, error) {
	// (1) Authenticate the desired-state: it MUST be signed by the deployment key held by cloud.
	if !agentcrypto.VerifyDeployment(a.enrollment.DeploymentPubKey, []byte(signed.PayloadB64), signed.Signature) {
		return false, fmt.Errorf("desired-state signature did not verify — refusing to apply")
	}
	ds := signed.Payload

	// (2) Decrypt sealed secrets locally. external_db is consumed for the DB connection; the rest
	// (R2 keys, etc.) merge into the plaintext config passed to the containers as env.
	resolved := map[string]string{}
	for k, v := range ds.Config {
		resolved[k] = v
	}
	var externalSecret []byte
	for name, ciphertext := range ds.SealedSecrets {
		plain, err := a.keys.OpenSealed(ciphertext)
		if err != nil {
			return false, fmt.Errorf("open sealed secret %q: %w", name, err)
		}
		if name == externalDBSecret {
			externalSecret = plain
			continue
		}
		resolved[name] = string(plain)
	}

	// (3) Resolve the DB connection — the mode branch.
	db, err := deploy.ResolveDBConn(ds, a.machine, externalSecret)
	if err != nil {
		return false, err
	}

	// (4) Ensure infra: network + host bind directories.
	if err := a.dx.EnsureNetwork(ctx, deploy.Network); err != nil {
		return false, err
	}
	for _, dir := range deploy.Dirs(a.cfg.StackRoot, ds) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return false, err
		}
	}

	keep := map[string]bool{}

	// (5) Managed mode: bring up Postgres (archive-aware), wait healthy, provision roles/schemas,
	// and — when the pgBackRest add-on is on — write its config, init the stanza, take a base backup.
	archiving := ds.Mode == cloudapi.ModeManaged && ds.AddOns.PgBackRest
	if ds.Mode == cloudapi.ModeManaged {
		if archiving {
			// Config must exist before Postgres boots so archive_command works from the first WAL.
			conf := deploy.RenderPgBackRestConf(ds, a.machine, resolved)
			confPath := filepath.Join(a.cfg.StackRoot, "pgbackrest", "pgbackrest.conf")
			if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
				return false, err
			}
		}
		pg := deploy.PostgresSpec(ds, a.machine, a.cfg.StackRoot, archiving)
		if err := deploy.Apply(ctx, a.dx, pg); err != nil {
			return false, fmt.Errorf("postgres: %w", err)
		}
		keep[pg.Name] = true
		if err := a.dx.WaitHealthy(ctx, deploy.SvcPostgres, 90*time.Second); err != nil {
			return false, err
		}
		if err := deploy.EnsureManagedDatabase(ctx, a.dx, a.machine); err != nil {
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

	// (6) Run migrations (owner conn) to completion before the app services roll.
	coreEnvBase := deploy.CoreEnvInput{
		Desired: ds, Machine: a.machine, DB: db,
		DeploymentPubKey: a.enrollment.DeploymentPubKey, ResolvedConfig: resolved,
	}
	if err := a.migrate(ctx, ds, coreEnvBase, resolved, db); err != nil {
		return false, err
	}

	// (7) Reconcile the core long-running services.
	serviceEnv := deploy.RenderServiceEnv(ds, a.machine, db, resolved)
	longRunning := []dockerx.RunSpec{
		deploy.RedisSpec(ds, a.machine),
		deploy.NatsSpec(ds),
		deploy.CommerceServiceSpec(ds, serviceEnv),
	}

	// (8) Gitea add-on: start it, then bootstrap the admin token BEFORE rendering core's env so
	// core boots already knowing GITEA_URL + GITEA_ADMIN_TOKEN and can create the app user + PAT.
	giteaProvisioned := false
	giteaURL, giteaToken := "", ""
	if ds.AddOns.Gitea {
		giteaSpec := deploy.GiteaSpec(ds, a.machine, db, a.cfg.StackRoot)
		if err := deploy.Apply(ctx, a.dx, giteaSpec); err != nil {
			return false, fmt.Errorf("gitea: %w", err)
		}
		keep[giteaSpec.Name] = true
		if err := a.dx.WaitHealthy(ctx, deploy.SvcGitea, 90*time.Second); err != nil {
			return false, err
		}
		token, err := gitea.ProvisionAdminToken(ctx, a.dx, a.machine, a.cfg.DataDir)
		if err != nil {
			return false, err
		}
		giteaURL = "http://" + deploy.SvcGitea + ":3000"
		giteaToken = token
		giteaProvisioned = true
	}

	// core-server rendered last so it carries the Gitea admin token when the add-on is on.
	coreEnvBase.GiteaURL = giteaURL
	coreEnvBase.GiteaAdminToken = giteaToken
	coreEnv := deploy.RenderCoreEnv(coreEnvBase)
	longRunning = append(longRunning, deploy.CoreServerSpec(ds, coreEnv, a.cfg.StackRoot))

	// (9) nginx (edge) add-on. pgBackRest is NOT a container — archiving lives in the Postgres
	// spec (step 5) and scheduled backups run via `docker exec` on the backup ticker.
	if ds.AddOns.Nginx {
		longRunning = append(longRunning, deploy.NginxSpec(ds, a.cfg.StackRoot))
	}

	for _, spec := range longRunning {
		if err := deploy.Apply(ctx, a.dx, spec); err != nil {
			return giteaProvisioned, fmt.Errorf("%s: %w", spec.Name, err)
		}
		keep[spec.Name] = true
	}

	// (10) Prune anything we own that is no longer in the desired set (e.g. a disabled add-on).
	if err := a.dx.PruneExcept(ctx, keep); err != nil {
		return giteaProvisioned, err
	}

	a.lastGeneration = ds.Generation
	return giteaProvisioned, nil
}

// migrate runs the core + commerce one-shot migration containers to completion.
func (a *Agent) migrate(ctx context.Context, ds cloudapi.DesiredState, coreEnvBase deploy.CoreEnvInput, resolved map[string]string, db deploy.DBConn) error {
	coreEnv := deploy.RenderCoreEnv(coreEnvBase)
	serviceEnv := deploy.RenderServiceEnv(ds, a.machine, db, resolved)

	runs := []struct {
		name  string
		image string
		env   []string
	}{
		{"core-migrate", ds.Images.CoreServer, coreEnv},
		{"commerce-migrate", ds.Images.CommerceService, serviceEnv},
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
