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
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/host"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secretprovider"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secrets"
)

// Version is the agent build version reported to cloud at enrollment.
const Version = "0.1.0"

// externalDBSecret is the reserved sealed-secret name carrying the external DB connection.
const externalDBSecret = "external_db"

// secretProviderPrefix marks sealed secrets that carry the SECRET half of the secret-store auth
// method. The suffix after the prefix is the reserved auth-secret name (clientSecret, token, ...).
// The prefix matches the `secretStore` component name cloud renamed the provider to.
const secretProviderPrefix = "secretStore."

// resyncInterval is the periodic full-reconcile cadence when the generation is unchanged and the
// last reconcile succeeded — it keeps drift corrected and the wildcard cert renewed without needing
// a generation bump (cert renewal is handled inside reconcile's EnsureWildcard).
const resyncInterval = 5 * time.Minute

// Retry cadences. fastRecheckInterval drives quick self-heal while Blocked on an operator action (DNS
// delegation or secret store) — the checks are cheap, so a ~10s re-check lands the stack within seconds
// of the records/config appearing. backoffBase→backoffCap is the exponential backoff after a genuine
// reconcile failure or a Let's Encrypt rate-limit, so we never hammer LE or a failing dependency.
const (
	fastRecheckInterval = 10 * time.Second
	backoffBase         = 30 * time.Second
	backoffCap          = 30 * time.Minute

	// heartbeatInterval is the periodic status-push cadence when nothing changes — it gives cloud and the
	// setup UI steady liveness/health even with no reconcile (transitions still report immediately, out of band).
	heartbeatInterval = 30 * time.Second
	// reconnectBackoff{Base,Cap} throttle re-opening the Subscribe stream after it drops (network blip, a
	// Cloudflare idle close, or a cloud restart) so we don't hammer on a persistent outage.
	reconnectBackoffBase = 2 * time.Second
	reconnectBackoffCap  = 1 * time.Minute
)

// Agent holds the long-lived collaborators for one deployment.
type Agent struct {
	cfg        *config.Config
	log        *slog.Logger
	keys       *agentcrypto.Keys
	machine    *secrets.Machine
	dx         *dockerx.Client
	cloud      *cloudapi.Client
	enrollment *cloudapi.Enrollment
	logs       *logManager // on-demand container log tailing (StartLogs/StopLogs)

	lastGeneration int64
	lastDesired    *cloudapi.DesiredState // last verified desired-state — re-applied on force-recheck / blocked self-heal
	archiving      bool                   // pgBackRest add-on currently enabled (drives the backup ticker)
	hadFullBackup  bool                   // a full backup has been taken since archiving was enabled
	edgeManaged    bool                   // agent runs nginx + the bundled acme-dns wildcard edge
	certs          []cloudapi.CertReport  // last observed managed-edge certs (reported each heartbeat)
	// acmeDelegation, when set, is the one-time CNAME the operator must add before the wildcard cert
	// can issue — surfaced in the heartbeat for the setup flow's DNS-Delegation step.
	acmeDelegation *cloudapi.AcmeChallengeDelegation

	// Generation gate + transition tracking (all touched from the single Run/select goroutine).
	lastReconcileErr    error     // non-nil forces a re-reconcile next tick until it clears
	lastResync          time.Time // last full-reconcile time (periodic resync cadence)
	lastErrMsg          string    // dedup: only emit a ReconcileError event when the message changes
	awaitingSecretStore bool      // blocked: cloud hasn't configured the secret store yet (operator action)
	awaitingDns         bool      // blocked: the wildcard DNS delegation isn't live yet (operator action)
	rateLimited         bool      // blocked: Let's Encrypt rate-limited us; serving out a backoff window
	hadCert             bool      // a wildcard cert has been observed on disk (emit WildcardIssued on 0→1)
	giteaProvisioned    bool      // the Gitea admin token has been provisioned (emit on transition)

	// Retry state. blocked = on the fast-recheck cadence (awaiting an operator action). backoff/nextAttempt
	// throttle retries after a genuine failure / LE rate-limit. curBlockReason dedups the edge block warn,
	// and emittedSteps dedups progress steps to once per generation so steady-state ticks stay quiet.
	blocked        bool
	backoff        time.Duration
	nextAttempt    time.Time
	curBlockReason string
	emittedSteps   map[string]int64
	// forceRecheckCh is a "check now" nudge (driven by the cloud ForceRecheck command over the Subscribe
	// stream) that clears the backoff window and re-applies the last desired-state immediately.
	forceRecheckCh chan struct{}

	// pendingEvents buffers notable transitions until the next heartbeat drains them.
	pendingEvents []cloudapi.Event
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

	return &Agent{
		cfg: cfg, log: log, keys: keys, machine: machine, dx: dx, cloud: cloud,
		forceRecheckCh: make(chan struct{}, 1),
	}, nil
}

// forceRecheck requests an immediate re-apply of the last desired-state on the next select iteration
// (the handler clears the backoff window first). Driven by the cloud ForceRecheck command over the stream.
func (a *Agent) forceRecheck() {
	select {
	case a.forceRecheckCh <- struct{}{}:
	default: // a recheck is already queued
	}
}

// streamMsg carries one Subscribe frame (or the terminal stream error) from the reader goroutine.
type streamMsg struct {
	event *cloudapi.ServerEvent
	err   error
}

// Run enrolls (once) then holds a live Subscribe stream: it applies each pushed desired-state, reports
// status on transitions plus a periodic heartbeat, self-heals while blocked, runs scheduled backups, and
// reconnects with backoff when the stream drops — until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	enr, err := enroll.Run(ctx, a.cloud, a.keys, a.cfg, Version)
	if err != nil {
		return err
	}
	a.enrollment = enr
	a.cloud.SetCredential(enr.AgentCredential)
	a.logs = newLogManager(ctx, a.dx, a.cloud, a.log)
	a.log.Info("enrolled", "deployment", a.cfg.DeploymentID)

	// Periodic status heartbeat (liveness/health) independent of desired-state changes.
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	// Periodic re-apply of the last desired-state (in memory) — drives cert renewal (reconcile's
	// EnsureWildcard) even when the generation is unchanged. New desired-state arrives via the Subscribe
	// push (and a reconnect re-delivers the current state), so no separate fetch is needed.
	resyncTicker := time.NewTicker(resyncInterval)
	defer resyncTicker.Stop()
	// Fast-recheck only fires while Blocked on an operator action (DNS delegation / secret store) so the
	// stack self-heals within ~10s of the records/config landing. Idle otherwise (guarded on a.blocked).
	fastTicker := time.NewTicker(fastRecheckInterval)
	defer fastTicker.Stop()
	// Backup schedule (only fires when the pgBackRest add-on is enabled): hourly incremental, full daily.
	backupTicker := time.NewTicker(time.Hour)
	defer backupTicker.Stop()
	backupTick := 0

	// Reconnect loop: open the stream, drain it in the inner select, reopen with backoff when it drops.
	reconnect := time.Duration(0)
	for {
		if ctx.Err() != nil {
			return nil
		}
		sub, err := a.cloud.Subscribe(ctx, a.lastGeneration)
		if err != nil {
			a.log.Warn("subscribe failed", "err", err)
			if !sleepBackoff(ctx, &reconnect) {
				return nil
			}
			continue
		}
		reconnect = 0
		a.log.Info("subscribed to desired-state stream")

		streamCtx, cancel := context.WithCancel(ctx)
		events := make(chan streamMsg, 8)
		go readStream(streamCtx, sub, events)

		connected := true
		for connected {
			select {
			case <-ctx.Done():
				cancel()
				_ = sub.Close()
				return nil
			case msg := <-events:
				if msg.err != nil {
					if ctx.Err() == nil {
						a.log.Warn("desired-state stream closed", "err", msg.err)
					}
					connected = false
					continue
				}
				a.handleServerEvent(ctx, msg.event)
			case <-heartbeatTicker.C:
				a.reportHeartbeat(ctx)
			case <-resyncTicker.C:
				a.reapply(ctx)
			case <-fastTicker.C:
				if a.blocked {
					a.reapply(ctx)
				}
			case <-a.forceRecheckCh:
				a.nextAttempt = time.Time{} // clear any backoff window so the retry runs now
				a.reapply(ctx)
			case <-backupTicker.C:
				a.runScheduledBackup(ctx, &backupTick)
			}
		}

		cancel()
		_ = sub.Close()
		if !sleepBackoff(ctx, &reconnect) {
			return nil
		}
	}
}

// readStream pumps the Subscribe stream into ch until it errors or ctx is cancelled.
func readStream(ctx context.Context, sub *cloudapi.Subscription, ch chan<- streamMsg) {
	for {
		ev, err := sub.Receive()
		if err != nil {
			select {
			case ch <- streamMsg{err: err}:
			case <-ctx.Done():
			}
			return
		}
		select {
		case ch <- streamMsg{event: ev}:
		case <-ctx.Done():
			return
		}
	}
}

// sleepBackoff grows the reconnect backoff (base→cap) and sleeps for it, returning false if ctx is cancelled.
func sleepBackoff(ctx context.Context, d *time.Duration) bool {
	switch {
	case *d == 0:
		*d = reconnectBackoffBase
	default:
		*d *= 2
		if *d > reconnectBackoffCap {
			*d = reconnectBackoffCap
		}
	}
	t := time.NewTimer(*d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// handleServerEvent dispatches one decoded Subscribe frame: apply a desired-state push, act on a command,
// or ignore a keepalive (liveness only).
func (a *Agent) handleServerEvent(ctx context.Context, ev *cloudapi.ServerEvent) {
	switch {
	case ev.DesiredState != nil:
		a.applySigned(ctx, ev.DesiredState)
	case ev.Command != nil:
		if ev.Command.ForceRecheck {
			a.log.Info("force-recheck command received")
			a.forceRecheck() // handled on the next select iteration (clears backoff + re-applies)
		}
		if ev.Command.RequestStatus {
			// On-demand cockpit paint: report current status immediately, no reconcile.
			a.reportHeartbeat(ctx)
		}
		if ev.Command.StartLogs != nil {
			a.logs.start(ev.Command.StartLogs.Target, int(ev.Command.StartLogs.TailLines), ev.Command.StartLogs.Since)
		}
		if ev.Command.StopLogs != nil {
			a.logs.stop(ev.Command.StopLogs.Target)
		}
	case ev.KeepAlive:
		// liveness frame only — nothing to do
	}
}

// applySigned authenticates a pushed/fetched signed desired-state and, if valid, applies it. A bad
// signature is refused (the signed bytes are the only source) and surfaced as a ReconcileError.
func (a *Agent) applySigned(ctx context.Context, signed *cloudapi.SignedDesiredState) {
	ds, err := a.verifyDesiredState(signed)
	if err != nil {
		a.log.Error("reject desired-state", "err", err)
		a.emitError(err.Error())
		cond := []cloudapi.Condition{readyCondition("false", "ReconcileError", err.Error())}
		a.report(ctx, a.lastGeneration, cond, a.collectServices(ctx))
		return
	}
	a.lastDesired = &ds
	a.applyDesired(ctx, ds)
}

// applyDesired runs the generation-gated reconcile for an already-verified desired-state, then reports
// status. Reconcile runs on a new generation, a lingering error, or the resync cadence — but not inside a
// backoff window (a genuine failure / LE rate-limit), so we never hammer.
func (a *Agent) applyDesired(ctx context.Context, ds cloudapi.DesiredState) {
	now := time.Now()
	inBackoff := a.backoff > 0 && now.Before(a.nextAttempt)
	if !inBackoff && (ds.Generation != a.lastGeneration || a.lastReconcileErr != nil || now.Sub(a.lastResync) >= resyncInterval) {
		a.lastResync = now
		rerr := a.reconcile(ctx, ds)
		a.lastReconcileErr = rerr
		if rerr != nil {
			a.log.Error("reconcile failed", "err", rerr)
			a.emitError(rerr.Error())
			a.enterBackoff() // genuine failure → exponential backoff before the next attempt
		} else {
			a.lastErrMsg = ""
		}
	}

	// Blocked (fast-recheck) = awaiting an operator action. Rate-limit/errors use the backoff cadence.
	a.blocked = a.awaitingSecretStore || a.awaitingDns

	services := a.collectServices(ctx)
	conditions := a.buildConditions(a.lastReconcileErr, services)
	a.report(ctx, a.lastGeneration, conditions, services)
}

// reapply re-runs applyDesired against the last verified desired-state — used by the force-recheck command
// and the blocked-state fast-recheck (re-check whether the operator's DNS / secret store is now in place).
func (a *Agent) reapply(ctx context.Context) {
	if a.lastDesired == nil {
		return
	}
	a.applyDesired(ctx, *a.lastDesired)
}

// reportHeartbeat pushes a status heartbeat (health snapshot + current conditions) without reconciling.
func (a *Agent) reportHeartbeat(ctx context.Context) {
	services := a.collectServices(ctx)
	conditions := a.buildConditions(a.lastReconcileErr, services)
	a.report(ctx, a.lastGeneration, conditions, services)
}

// runScheduledBackup takes a scheduled pgBackRest backup when the add-on is enabled: incremental hourly,
// full every 24th tick (daily). The initial full is taken at enable time inside reconcile.
func (a *Agent) runScheduledBackup(ctx context.Context, tick *int) {
	if !a.archiving {
		return
	}
	*tick++
	bt := "incr"
	if *tick%24 == 0 {
		bt = "full"
	}
	if err := deploy.RunBackup(ctx, a.dx, bt); err != nil {
		a.log.Warn("scheduled backup failed", "type", bt, "err", err)
		a.emit("warn", "database", "BackupFailed", fmt.Sprintf("Scheduled %s backup failed: %v", bt, err))
	} else {
		a.log.Info("scheduled backup complete", "type", bt)
		a.emit("info", "database", "BackupComplete", fmt.Sprintf("Scheduled %s backup complete.", bt))
	}
}

// enterBackoff grows the exponential backoff (base→cap) and sets the next allowed attempt time.
func (a *Agent) enterBackoff() {
	switch {
	case a.backoff == 0:
		a.backoff = backoffBase
	default:
		a.backoff *= 2
		if a.backoff > backoffCap {
			a.backoff = backoffCap
		}
	}
	a.nextAttempt = time.Now().Add(a.backoff)
}

// resetBackoff clears the backoff window after a clean reconcile / successful issuance.
func (a *Agent) resetBackoff() {
	a.backoff = 0
	a.nextAttempt = time.Time{}
}

// step emits an info progress event once per generation (deduped), so a new generation logs each phase
// to the cloud timeline while steady-state resync ticks stay quiet.
func (a *Agent) step(generation int64, component, reason, message string) {
	if a.emittedSteps == nil {
		a.emittedSteps = map[string]int64{}
	}
	if g, ok := a.emittedSteps[reason]; ok && g == generation {
		return
	}
	a.emittedSteps[reason] = generation
	a.emit("info", component, reason, message)
}

// emitBlock emits an operator-action block event once per distinct reason (deduped on curBlockReason),
// so a steady Blocked state doesn't repeat the same warn every tick.
func (a *Agent) emitBlock(level, component, reason, message string) {
	if a.curBlockReason == reason {
		return
	}
	a.curBlockReason = reason
	a.emit(level, component, reason, message)
}

// nowRFC is the RFC3339 transition timestamp stamped on conditions.
func nowRFC() string { return time.Now().UTC().Format(time.RFC3339) }

// readyCondition builds a single Ready condition with the given status/reason/message.
func readyCondition(status, reason, message string) cloudapi.Condition {
	return cloudapi.Condition{Type: "Ready", Status: status, Reason: reason, Message: message, Since: nowRFC()}
}

// buildConditions derives the reported conditions from the reconcile outcome + observed service
// health, as a strict priority ladder (error → blocked → degraded → reconciling → in-sync).
func (a *Agent) buildConditions(reconcileErr error, services []cloudapi.ServiceStatus) []cloudapi.Condition {
	if reconcileErr != nil {
		return []cloudapi.Condition{
			readyCondition("false", "ReconcileError", reconcileErr.Error()),
			{Type: "Degraded", Status: "true", Reason: "ReconcileError", Message: reconcileErr.Error(), Since: nowRFC()},
		}
	}
	if a.awaitingSecretStore {
		msg := "Waiting for the secret store to be configured before provisioning."
		return []cloudapi.Condition{
			readyCondition("false", "AwaitingSecretStore", msg),
			{Type: "Blocked", Status: "true", Reason: "AwaitingSecretStore", Component: "secretStore", Message: msg, Since: nowRFC()},
		}
	}
	if a.rateLimited {
		msg := "Let's Encrypt rate limit reached; backing off before retrying certificate issuance."
		return []cloudapi.Condition{
			readyCondition("false", "RateLimited", msg),
			{Type: "Blocked", Status: "true", Reason: "RateLimited", Component: "edge", Message: msg, Since: nowRFC()},
		}
	}
	if a.awaitingDns {
		msg := "Add the DNS delegation records so the wildcard certificate can be issued."
		return []cloudapi.Condition{
			readyCondition("false", "AwaitingDnsDelegation", msg),
			{Type: "Blocked", Status: "true", Reason: "AwaitingDnsDelegation", Component: "edge", Message: msg, Since: nowRFC()},
		}
	}

	var unhealthy, starting []string
	for _, s := range services {
		switch {
		case s.Health == "unhealthy" || s.State == "exited" || s.State == "dead":
			unhealthy = append(unhealthy, s.Service)
		case s.Health == "starting" || s.State == "restarting" || s.State == "created":
			starting = append(starting, s.Service)
		}
	}
	if len(unhealthy) > 0 {
		msg := "Unhealthy services: " + strings.Join(unhealthy, ", ") + "."
		return []cloudapi.Condition{
			readyCondition("false", "ServiceUnhealthy", msg),
			{Type: "Degraded", Status: "true", Reason: "ServiceUnhealthy", Message: msg, Since: nowRFC()},
		}
	}
	if len(starting) > 0 {
		msg := "Services still starting: " + strings.Join(starting, ", ") + "."
		return []cloudapi.Condition{
			readyCondition("false", "Reconciling", msg),
			{Type: "Reconciling", Status: "true", Reason: "Reconciling", Message: msg, Since: nowRFC()},
		}
	}
	return []cloudapi.Condition{readyCondition("true", "InSync", "All services healthy and in sync.")}
}

// emit buffers a notable transition for the next heartbeat.
func (a *Agent) emit(level, component, reason, message string) {
	a.pendingEvents = append(a.pendingEvents, cloudapi.Event{Level: level, Component: component, Reason: reason, Message: message})
}

// emitError records a ReconcileError event, deduped so a persistent failure isn't emitted every tick.
func (a *Agent) emitError(msg string) {
	if msg == a.lastErrMsg {
		return
	}
	a.lastErrMsg = msg
	a.emit("error", "", "ReconcileError", msg)
}

// componentForService maps a service name to the component it belongs to (see the shared contract).
func componentForService(svc string) string {
	switch svc {
	case deploy.SvcPostgres:
		return "database"
	case deploy.SvcCore, deploy.SvcCommerce, deploy.SvcNats, deploy.SvcRedis:
		return "core"
	case deploy.SvcNginx, deploy.SvcAcmeDns:
		return "edge"
	case deploy.SvcGitea:
		return "gitea"
	default:
		return ""
	}
}

// collectServices reads each owned container's state + health + a resource sample, tagged by component.
func (a *Agent) collectServices(ctx context.Context) []cloudapi.ServiceStatus {
	statuses, _ := a.dx.List(ctx)
	services := make([]cloudapi.ServiceStatus, 0, len(statuses))
	for _, s := range statuses {
		ss := cloudapi.ServiceStatus{
			Component: componentForService(s.Service),
			Service:   s.Service,
			Name:      s.Name,
			State:     s.State,
			Health:    s.Health,
		}
		if sample, err := a.dx.Stats(ctx, s.Name); err == nil {
			ss.CPUPercent = sample.CPUPercent
			ss.MemoryBytes = sample.MemoryBytes
		}
		services = append(services, ss)
	}
	return services
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

// reconcile drives the stack toward one already-verified desired-state.
func (a *Agent) reconcile(ctx context.Context, ds cloudapi.DesiredState) error {
	// (1) Resolve the stack composition from components (nil = component absent). The DB defaults to
	// managed unless explicitly external; the edge/gitea are off unless their component says otherwise.
	dbExternal := ds.Components.Database != nil && ds.Components.Database.Mode == cloudapi.ModeExternal
	dbManaged := !dbExternal
	pgBackRest := dbManaged && ds.Components.Database != nil && ds.Components.Database.Backup != nil
	giteaEnabled := ds.Components.Gitea != nil && ds.Components.Gitea.Enabled

	// (2) Decrypt the sealed secrets once. Names prefixed `secretStore.` carry the SECRET half of
	// the secret-store auth method (client secret, token, jwt, ...) — strip the prefix into
	// authSecrets. The reserved `external_db` name carries the external-mode DB connection.
	authSecrets := map[string]string{}
	var externalSecret []byte
	for name, ciphertext := range ds.SealedSecrets {
		plain, err := a.keys.OpenSealed(ciphertext)
		if err != nil {
			return fmt.Errorf("open sealed secret %q: %w", name, err)
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
	// The secret store is configured post-create in the in-view setup flow, so it can be nil for a
	// while at first reconcile. Treat that as a steady operator-action block (like the DNS delegation):
	// early-return without an error so we keep re-running each tick — without advancing lastGeneration
	// or setting lastReconcileErr — until cloud supplies it. No event (it's a block, not a transition).
	if ds.Components.SecretStore == nil {
		a.awaitingSecretStore = true
		return nil
	}
	a.awaitingSecretStore = false
	provider, err := secretprovider.New(ctx, *ds.Components.SecretStore, authSecrets)
	if err != nil {
		return fmt.Errorf("secret provider: %w", err)
	}
	coreEnv, err := provider.Fetch(ctx, "/core-server")
	if err != nil {
		return fmt.Errorf("secrets /core-server: %w", err)
	}
	commerceEnv, err := provider.Fetch(ctx, "/commerce-service")
	if err != nil {
		return fmt.Errorf("secrets /commerce-service: %w", err)
	}
	agentEnv, err := provider.Fetch(ctx, "/agent")
	if err != nil {
		return fmt.Errorf("secrets /agent: %w", err)
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
		return err
	}

	// (6) Ensure infra: network + host bind directories.
	if err := a.dx.EnsureNetwork(ctx, deploy.Network); err != nil {
		return err
	}
	for _, dir := range deploy.Dirs(a.cfg.StackRoot, ds) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	// The core-server / commerce-service containers run as uid 1001 (nestjs) and write to their
	// bind-mounted /app/logs — hand the host log dir to that uid, else the app boots then crashes with
	// "EACCES: permission denied, open 'logs/…'". Applies in both DB modes (the app always logs).
	if err := os.Chown(deploy.CoreLogDir(a.cfg.StackRoot), deploy.CoreServerUID, deploy.CoreServerUID); err != nil {
		return fmt.Errorf("chown core log dir: %w", err)
	}
	// MkdirAll creates the pgdata dir owned by the (root) agent, but the postgres container runs as
	// uid 999 and must be able to write its bind-mounted data dir — hand ownership over, else initdb
	// fails with "mkdir: cannot create directory '/var/lib/postgresql/data': Permission denied".
	if dbManaged {
		if err := os.Chown(deploy.PostgresDataDir(a.cfg.StackRoot), deploy.PostgresUID, deploy.PostgresUID); err != nil {
			return fmt.Errorf("chown postgres data dir: %w", err)
		}
	}

	keep := map[string]bool{}

	// (6.5) Managed edge, CERT-FIRST: bring up acme-dns and issue the single *.<base> wildcard BEFORE
	// provisioning, and GATE the stack on it. This means the app containers never start until the
	// operator's DNS is in place and the cert exists — no point serving nothing over TLS. edge=external
	// skips this (a BYO ingress/LB fronts core, so the agent runs no nginx/acme-dns).
	a.edgeManaged = ds.Components.Edge != nil && ds.Components.Edge.Mode == cloudapi.EdgeManaged && ds.BaseDomain != ""
	if a.edgeManaged {
		keep[deploy.SvcAcmeDns] = true
		// Pre-flight-guarded issuance: EnsureWildcard only calls Let's Encrypt once the delegation
		// actually resolves (or on the very first register), so DNS propagation no longer produces a
		// ReconcileError burst. Categorize the outcome into the right condition/event/cadence.
		res, werr := deploy.EnsureWildcard(ctx, a.dx, ds, a.cfg.StackRoot, a.acmeDelegation)
		a.certs = res.Certs
		switch res.Outcome {
		case deploy.WildcardOutcomeAwaitingDNS:
			// Operator must add/propagate the DNS records — a steady block, not a failure. Log the step
			// once/gen, warn once, keep acme-dns running, and re-check on the fast cadence. No error.
			a.acmeDelegation = res.Delegation
			a.awaitingDns, a.rateLimited = true, false
			a.step(ds.Generation, "edge", "IssuingWildcard", fmt.Sprintf("Issuing wildcard certificate for *.%s.", ds.BaseDomain))
			a.emitBlock("warn", "edge", "AwaitingDnsDelegation",
				"Waiting for the DNS delegation records to propagate before the wildcard certificate can be issued.")
			if werr != nil {
				a.log.Warn("awaiting dns delegation", "err", werr)
			}
			return nil
		case deploy.WildcardOutcomeRateLimited:
			// LE throttled us — enter backoff and hold; not a failure, so no ReconcileError.
			a.awaitingDns, a.rateLimited = false, true
			a.emitBlock("warn", "edge", "RateLimited",
				"Let's Encrypt rate limit reached; backing off before retrying certificate issuance.")
			a.log.Warn("lets-encrypt rate limited", "err", werr)
			a.enterBackoff()
			return nil
		case deploy.WildcardOutcomeError:
			// Genuine issuance failure (account/network/LE hard error) — surface as a ReconcileError.
			return werr
		}
		// WildcardOutcomeIssued — the wildcard is in place; clear blocks and continue provisioning.
		a.acmeDelegation = nil
		a.awaitingDns, a.rateLimited, a.curBlockReason = false, false, ""
		a.resetBackoff()
		if !a.hadCert {
			a.hadCert = true
			a.emit("info", "edge", "WildcardIssued", fmt.Sprintf("Wildcard certificate issued for *.%s.", ds.BaseDomain))
		}
	} else {
		a.acmeDelegation = nil
		a.certs = nil
		a.awaitingDns, a.rateLimited, a.curBlockReason = false, false, ""
	}

	// (7) Managed mode: bring up Postgres (archive-aware), wait healthy, provision roles/schemas,
	// and — when the pgBackRest add-on is on — write its config, init the stanza, take a base backup.
	archiving := pgBackRest
	if dbManaged {
		a.step(ds.Generation, "database", "ProvisioningDatabase", "Provisioning the managed Postgres database.")
		if archiving {
			a.step(ds.Generation, "database", "EnablingBackups", "Enabling pgBackRest backups for the managed database.")
			// Config must exist before Postgres boots so archive_command works from the first WAL.
			// The S3-compatible OFFSITE backup creds (S3_*) live in a DEDICATED `/backup` secret-store
			// folder — NOT `/core-server` (whose bucket is the app's media store). Best-effort: if
			// `/backup` is absent/empty, pgBackRest runs local-repo only. pg1-user = real superuser.
			backupEnv, err := provider.Fetch(ctx, "/backup")
			if err != nil {
				a.log.Warn("fetch /backup secrets failed — pgBackRest runs local-repo only", "err", err)
				backupEnv = map[string]string{}
			}
			confDir := deploy.PgBackRestConfDir(a.cfg.StackRoot)
			confPath := filepath.Join(confDir, "pgbackrest.conf")
			conf := deploy.RenderPgBackRestConf(ds, a.machine, backupEnv, db.OwnerUser)
			if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
				return err
			}
			// pgBackRest runs as the postgres OS user (uid 999) and must READ this config + WRITE the
			// local repo — hand the conf dir, the conf file, and the repo dir to that uid, else it fails
			// "permission denied" on the root-owned mount.
			for _, path := range []string{confDir, confPath, deploy.PgBackRestRepoDir(a.cfg.StackRoot)} {
				if err := os.Chown(path, deploy.PostgresUID, deploy.PostgresUID); err != nil {
					return fmt.Errorf("chown %s: %w", path, err)
				}
			}
		}
		pg := deploy.PostgresSpec(ds, db, a.cfg.StackRoot, archiving)
		if err := deploy.Apply(ctx, a.dx, pg); err != nil {
			return fmt.Errorf("postgres: %w", err)
		}
		keep[pg.Name] = true
		if err := a.dx.WaitHealthy(ctx, deploy.SvcPostgres, 90*time.Second); err != nil {
			return err
		}
		if err := deploy.EnsureManagedDatabase(ctx, a.dx, db); err != nil {
			return err
		}
		if archiving {
			if err := deploy.EnsureStanza(ctx, a.dx); err != nil {
				return err
			}
			if !a.hadFullBackup {
				if err := deploy.RunBackup(ctx, a.dx, "full"); err != nil {
					return err
				}
				a.hadFullBackup = true
				a.emit("info", "database", "BackupComplete", "Initial full backup complete.")
			}
		}
	}
	a.archiving = archiving
	// pgBackRest turned off since the last reconcile — reset so a re-enable takes a fresh base backup.
	if !archiving {
		a.hadFullBackup = false
	}

	// (8) Render the commerce env verbatim, then run migrations (owner conn) to completion before the
	// app services roll. core-migrate runs without the Gitea additions (they aren't needed for DDL).
	commerceEnvSlice := deploy.RenderServiceEnv(commerceEnv)
	a.step(ds.Generation, "core", "RunningMigrations", "Running database migrations.")
	if err := a.migrate(ctx, ds, deploy.RenderCoreEnv(coreEnv, ds.BaseDomain, "", ""), commerceEnvSlice); err != nil {
		return err
	}

	// (9) Reconcile the core long-running services.
	longRunning := []dockerx.RunSpec{
		deploy.RedisSpec(ds, prov.RedisPassword),
		deploy.NatsSpec(ds),
		deploy.CommerceServiceSpec(ds, commerceEnvSlice),
	}

	// (10) Gitea add-on: start it, then bootstrap the admin token BEFORE rendering core's env so
	// core boots already knowing GITEA_BASE_URL + GITEA_ADMIN_TOKEN and can create the app user + PAT.
	giteaURL, giteaToken := "", ""
	if giteaEnabled {
		a.step(ds.Generation, "gitea", "ProvisioningGitea", "Provisioning the Gitea add-on.")
		// gitea runs as uid 1000 and writes its bind-mounted /data — hand ownership over, else it
		// crashes reading /data/gitea/conf/app.ini with "permission denied" on the root-owned mount.
		if err := os.Chown(deploy.GiteaDataDir(a.cfg.StackRoot), deploy.GiteaUID, deploy.GiteaUID); err != nil {
			return fmt.Errorf("chown gitea data dir: %w", err)
		}
		giteaSpec := deploy.GiteaSpec(ds, db, a.cfg.StackRoot)
		if err := deploy.Apply(ctx, a.dx, giteaSpec); err != nil {
			return fmt.Errorf("gitea: %w", err)
		}
		keep[giteaSpec.Name] = true
		if err := a.dx.WaitHealthy(ctx, deploy.SvcGitea, 90*time.Second); err != nil {
			return err
		}
		token, err := gitea.ProvisionAdminToken(ctx, a.dx, giteaAdminUser, giteaAdminPw, a.cfg.DataDir)
		if err != nil {
			return err
		}
		giteaURL = "http://" + deploy.SvcGitea + ":3000"
		giteaToken = token
		if !a.giteaProvisioned {
			a.giteaProvisioned = true
			a.emit("info", "gitea", "GiteaProvisioned", "Gitea provisioned; admin token stored.")
		}
	} else {
		// Add-on off — reset so a later re-enable re-announces provisioning on the timeline.
		a.giteaProvisioned = false
	}

	// core-server rendered last so it carries the Gitea admin token when the add-on is on.
	coreEnvSlice := deploy.RenderCoreEnv(coreEnv, ds.BaseDomain, giteaURL, giteaToken)
	longRunning = append(longRunning, deploy.CoreServerSpec(ds, coreEnvSlice, a.cfg.StackRoot))

	a.step(ds.Generation, "core", "StartingServices", "Starting the core services (redis, nats, commerce, core-server).")
	for _, spec := range longRunning {
		if err := deploy.Apply(ctx, a.dx, spec); err != nil {
			return fmt.Errorf("%s: %w", spec.Name, err)
		}
		keep[spec.Name] = true
	}

	// (11) Managed edge: the wildcard already exists (step 6.5) and the stack is now up, so render the
	// derived routes (api./git./*.) + sync the web bundles and (re)start nginx — it comes up serving
	// HTTPS immediately. edge=external means a BYO ingress/LB fronts core: no nginx, no acme-dns.
	if a.edgeManaged {
		certs, err := deploy.EnsureNginx(ctx, a.dx, ds, a.cfg.StackRoot, coreEnvSlice)
		if err != nil {
			return err
		}
		a.certs = certs
		keep[deploy.SvcNginx] = true
		keep[deploy.SvcAcmeDns] = true
	}

	// (12) Prune anything we own that is no longer in the desired set (e.g. a disabled add-on).
	if err := a.dx.PruneExcept(ctx, keep); err != nil {
		return err
	}

	// Fully converged: clear any lingering block/backoff state and log completion once per generation.
	a.curBlockReason = ""
	a.resetBackoff()
	a.step(ds.Generation, "core", "ReconcileComplete", "All components reconciled and in sync.")
	a.lastGeneration = ds.Generation
	return nil
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

// report pushes a heartbeat with conditions, per-service state, host metrics, certs, delegation, and
// any buffered events; failures are logged, not fatal (buffered events are re-queued on failure).
func (a *Agent) report(ctx context.Context, generation int64, conditions []cloudapi.Condition, services []cloudapi.ServiceStatus) {
	// Whole-VM resource usage — disk read from the stack root (a host bind-mount → the VM's fs).
	hm := host.Collect(a.cfg.StackRoot)
	events := a.pendingEvents
	a.pendingEvents = nil
	err := a.cloud.ReportStatus(ctx, cloudapi.StatusReport{
		DeploymentID: a.cfg.DeploymentID,
		Generation:   generation,
		Conditions:   conditions,
		Services:     services,
		Certificates: a.certs,
		Delegation:   a.acmeDelegation,
		Events:       events,
		Host: &cloudapi.HostMetrics{
			CPUPercent:     hm.CPUPercent,
			MemTotalBytes:  hm.MemTotalBytes,
			MemUsedBytes:   hm.MemUsedBytes,
			DiskTotalBytes: hm.DiskTotalBytes,
			DiskUsedBytes:  hm.DiskUsedBytes,
		},
	})
	if err != nil {
		a.log.Warn("status report failed", "err", err)
		// Re-queue the drained events so a transient report failure doesn't drop timeline entries.
		a.pendingEvents = append(events, a.pendingEvents...)
	}
}

// tailLog trims migration output to a readable tail for error messages.
func tailLog(s string) string {
	if len(s) > 2000 {
		return "…" + s[len(s)-2000:]
	}
	return s
}
