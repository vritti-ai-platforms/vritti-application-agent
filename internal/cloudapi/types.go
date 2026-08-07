// Package cloudapi defines the wire contract between the agent and cloud-server and a
// thin signed HTTP client for it. Cloud is a config + ciphertext relay: it never sees
// machine secrets, and human-entered secrets reach it only as sealed ciphertext.
package cloudapi

// DBMode selects how the deployment's Postgres is provided.
type DBMode string

const (
	// ModeManaged  — the agent runs a containerized Postgres and owns its lifecycle.
	ModeManaged DBMode = "managed"
	// ModeExternal — the operator brings their own DB; connection arrives as a sealed secret.
	ModeExternal DBMode = "external"
)

// EdgeMode selects how the deployment's HTTP edge (nginx + TLS) is provided. nginx is a core
// service, on by default (managed); external is the deliberate opt-out for deployments fronted by
// something else (the shared vm1 edge, a customer LB/ingress, or a tunnel).
type EdgeMode string

const (
	// EdgeManaged  — the agent runs nginx and issues a single *.<base> wildcard cert in-process
	// (lego DNS-01 via the bundled acme-dns). Routing is derived from BaseDomain, not operator-mapped.
	EdgeManaged EdgeMode = "managed"
	// EdgeExternal — something else fronts core; the agent runs no nginx and issues no certs.
	EdgeExternal EdgeMode = "external"
)

// DomainRoute is one host the managed edge serves (and obtains a cert for) plus its upstream.
type DomainRoute struct {
	Host     string `json:"host"`     // e.g. api.apw1.vrittiai.com
	Upstream string `json:"upstream"` // e.g. core-server:3002
}

// CertReport is the state of one obtained certificate, reported back to cloud (the system of record).
type CertReport struct {
	Host     string `json:"host"`
	NotAfter string `json:"notAfter"` // RFC3339 expiry
	IssuedAt string `json:"issuedAt"` // RFC3339 not-before
}

// AcmeChallengeDelegation is the DNS the operator must add so the agent's local acme-dns can answer
// the wildcard DNS-01 challenge. Surfaced in the heartbeat (→ wizard's DNS-Delegation step) until the
// cert is issued; nil once issued. THREE records are required:
//
//  1. Nameserver A:   `<Nameserver> A <ServerIP>` — resolves the acme-dns nameserver. Nameserver is a
//     SIBLING of the zone (ns.<base>, NOT under acme.<base>), so the parent DNS resolves it with no
//     in-zone glue — this is what makes it work on Cloudflare (self-referential glue does not).
//  2. Zone delegation: `<Zone> NS <Nameserver>` — delegates the challenge zone to that nameserver.
//  3. Challenge CNAME: `<Name> CNAME <Target>` — per acme-dns account; points at the delegated zone.
//
// (1)+(2) are one-time/stable; (3)'s target changes if acme-dns re-registers (a data wipe).
type AcmeChallengeDelegation struct {
	Name       string `json:"name"`       // CNAME record name: _acme-challenge.<base>
	Target     string `json:"target"`     // CNAME record value: <id>.acme.<base>
	Zone       string `json:"zone"`       // NS record name (the delegated zone): acme.<base>
	Nameserver string `json:"nameserver"` // NS record value AND the A record name: ns.<base>
	ServerIP   string `json:"serverIp"`   // A record value — the VM's public IP
}

// WebBundle is one static web artifact (OCI, a gzipped bundle) the managed edge serves off the
// wildcard origin. Path "" is the host SPA (core-web) at web root; a non-empty Path (e.g. "commerce")
// is a module-federation remote extracted to that subdir, so core-web loads it same-origin at
// /<path>/mf-manifest.json. Cloud picks the set per the deployment's entitled features.
type WebBundle struct {
	Artifact string `json:"artifact"` // e.g. ghcr.io/vritti-ai-platforms/core-web:latest-main
	Path     string `json:"path"`     // "" = web root; "commerce" = /commerce subdir
}

// Images is the set of resolved, pinned image references for a deployment's stack.
type Images struct {
	CoreServer      string `json:"coreServer"`
	CommerceService string `json:"commerceService"`
	Postgres        string `json:"postgres"` // postgres+pgBackRest image, pinned major (e.g. :18)
	Redis           string `json:"redis"`
	Nats            string `json:"nats"`
	Gitea           string `json:"gitea"`
	Nginx           string `json:"nginx"`
}

// SecretProviderAuth selects how the agent authenticates to the secret store. Non-secret params
// (identity id, client id, token/key file paths, region, resource, username, ...) live in Params;
// the SECRET half of each method (client secret, token, jwt, password, OCI private key/passphrase,
// k8s service-account token) arrives on the SealedSecrets channel under a reserved name so cloud
// never sees it. Method mirrors the Infisical SDK: universal | token | aws-iam | gcp-iam |
// gcp-id-token | azure | kubernetes | kubernetes-token | oidc | jwt | ldap | oci.
type SecretProviderAuth struct {
	Method string            `json:"method"`
	Params map[string]string `json:"params"`
}

// SecretProvider is the per-deployment secret store config CLOUD supplies (configured in cloud-web),
// so the generic agent hardcodes nothing. Type is the backend (currently "infisical"); the rest
// locates the store and picks the auth method.
type SecretProvider struct {
	Type      string             `json:"type"`
	URL       string             `json:"url"`
	ProjectID string             `json:"projectId"`
	Env       string             `json:"env"`
	Auth      SecretProviderAuth `json:"auth"`
}

// CoreComponent is the core stack the agent runs (core-server / commerce-service / nats / redis).
type CoreComponent struct {
	Enabled bool `json:"enabled"`
}

// DatabaseBackup is the pgBackRest config for a managed database; presence = the backup add-on is on.
type DatabaseBackup struct {
	Retention int `json:"retention"` // full backups kept (repo*-retention-full); <1 falls back to 4
}

// DatabaseComponent selects how Postgres is provided. managed = the agent runs its own containerized
// Postgres; external = the operator brings their own DB (connection arrives as a sealed secret).
type DatabaseComponent struct {
	Mode   DBMode          `json:"mode"`
	Backup *DatabaseBackup `json:"backup,omitempty"` // pgBackRest config — only valid when mode=managed
}

// EdgeComponent selects how the HTTP edge (nginx + TLS) is provided. managed = the agent runs nginx
// and issues the *.<base> wildcard; external = something else fronts core (no nginx, no certs).
type EdgeComponent struct {
	Mode      EdgeMode `json:"mode"`
	AcmeEmail string   `json:"acmeEmail,omitempty"` // Let's Encrypt registration email (required when managed)
}

// GiteaComponent is the post-setup opt-in Gitea add-on.
type GiteaComponent struct {
	Enabled bool `json:"enabled"`
}

// Components is the resolved stack composition the agent reconciles toward. Absent components are nil:
// core is always present; database/edge/gitea/secretStore are nil when the deployment omits them.
type Components struct {
	Core        CoreComponent      `json:"core"`
	Database    *DatabaseComponent `json:"database"`
	Edge        *EdgeComponent     `json:"edge"`
	Gitea       *GiteaComponent    `json:"gitea"`
	SecretStore *SecretProvider    `json:"secretStore"` // per-deployment secret store (cloud-provided); nil = none
}

// DesiredState is what cloud wants running; the agent reconciles toward it. Cloud SIGNS this
// with the deployment private key and the agent verifies with the deployment public key.
type DesiredState struct {
	Generation    int64             `json:"generation"` // monotonic; agent skips reconcile if unchanged
	DeploymentID  string            `json:"deploymentId"`
	Version       string            `json:"version"`     // pinned catalog/app version reference
	SpecVersion   int               `json:"specVersion"` // spec schema version
	BaseDomain    string            `json:"baseDomain"`  // e.g. dev.vrittiai.com / apw1.vrittiai.com
	Components    Components        `json:"components"`  // the resolved stack composition to reconcile toward
	AcmeStaging   bool              `json:"acmeStaging"` // use the LE staging CA (avoids rate limits while testing)
	Images        Images            `json:"images"`
	WebBundles    []WebBundle       `json:"webBundles"`    // static web artifacts the managed edge serves off *.<base>
	Config        map[string]string `json:"config"`        // plaintext non-secret config (R2 bucket names, tunables)
	SealedSecrets map[string]string `json:"sealedSecrets"` // name -> base64 sealed ciphertext (agent decrypts)
}

// SignedDesiredState wraps the canonical desired-state JSON with cloud's signature over exactly
// those bytes. The agent verifies the signature over PayloadB64 and then unmarshals THOSE bytes
// into a DesiredState — there is no separate unverified payload object to act on by mistake.
type SignedDesiredState struct {
	PayloadB64 string `json:"payloadB64"` // canonical desired-state JSON the signature is computed over
	Signature  string `json:"signature"`  // base64 Ed25519 signature by the deployment key
}

// EnrollRequest is sent once, presenting the one-time token and the agent's fresh public keys.
type EnrollRequest struct {
	DeploymentID  string `json:"deploymentId"`
	EnrollToken   string `json:"enrollToken"`
	SigningPubKey string `json:"signingPubKey"` // agent Ed25519 public (agent→cloud auth)
	SealingPubKey string `json:"sealingPubKey"` // agent X25519 public (seal target)
	AgentVersion  string `json:"agentVersion"`
}

// EnrollResponse returns the long-lived agent credential and the deployment public key used
// to verify everything cloud signs afterward, plus a signed nonce for the connectivity test.
type EnrollResponse struct {
	AgentCredential  string `json:"agentCredential"`  // bearer used on every subsequent request
	DeploymentPubKey string `json:"deploymentPubKey"` // base64 Ed25519 public (cloud→agent verify)
	Nonce            string `json:"nonce"`            // random challenge string
	NonceSignature   string `json:"nonceSignature"`   // signed by the deployment private key
}

// Enrollment is the cached result of a successful enroll, persisted locally.
type Enrollment struct {
	AgentCredential  string `json:"agentCredential"`
	DeploymentPubKey string `json:"deploymentPubKey"`
}

// HostMetrics is the VM's resource usage at heartbeat time (whole-VM, not per-container).
type HostMetrics struct {
	CPUPercent     float64          `json:"cpuPercent"`
	MemTotalBytes  uint64           `json:"memTotalBytes"`
	MemUsedBytes   uint64           `json:"memUsedBytes"`
	DiskTotalBytes uint64           `json:"diskTotalBytes"`
	DiskUsedBytes  uint64           `json:"diskUsedBytes"`
	DiskBreakdown  []DiskUsageEntry `json:"diskBreakdown,omitempty"`
}

// DiskUsageEntry is one labelled slice of the VM's used disk (docker images/containers, database, backups,
// gitea, certificates, logs, other).
type DiskUsageEntry struct {
	Name  string `json:"name"`
	Bytes uint64 `json:"bytes"`
}

// Condition is one reconcile-condition the agent reports (Kubernetes-style status). Type is one of
// Ready | Reconciling | Blocked | Degraded; Status is true | false | unknown; Reason is a machine
// code (InSync | Reconciling | ReconcileError | AwaitingDnsDelegation | ServiceUnhealthy).
type Condition struct {
	Type      string `json:"type"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Component string `json:"component,omitempty"` // core | database | edge | gitea | secretStore
	Since     string `json:"since"`               // RFC3339 transition timestamp
}

// ServiceStatus is a single service's runtime status in a heartbeat, tagged with its component.
type ServiceStatus struct {
	Component   string  `json:"component"` // core | database | edge | gitea
	Service     string  `json:"service"`
	Name        string  `json:"name"`
	State       string  `json:"state"`
	Health      string  `json:"health"`
	CPUPercent  float64 `json:"cpuPercent"`
	MemoryBytes uint64  `json:"memoryBytes"`
}

// Event is one notable transition the agent asks cloud to record on the deployment timeline.
type Event struct {
	Level     string `json:"level"`               // info | warn | error
	Component string `json:"component,omitempty"` // core | database | edge | gitea | secretStore
	Reason    string `json:"reason"`              // machine reason code
	Message   string `json:"message"`
}

// StatusReport is the periodic heartbeat the agent pushes to cloud.
type StatusReport struct {
	DeploymentID string          `json:"deploymentId"`
	Generation   int64           `json:"generation"` // desired-state generation currently applied
	Conditions   []Condition     `json:"conditions"` // reconcile conditions observed by the agent
	Services     []ServiceStatus `json:"services"`   // per-service runtime states, tagged by component
	Host         *HostMetrics    `json:"host,omitempty"`
	// Certificates report each managed-edge cert's expiry so cloud can track/alert (system of record).
	Certificates []CertReport `json:"certificates,omitempty"`
	// Delegation, when non-nil, is the one-time CNAME the operator must add before the wildcard cert
	// can be issued (present while the edge is Blocked awaiting the operator, absent once issued).
	Delegation *AcmeChallengeDelegation `json:"delegation,omitempty"`
	// Events are notable transitions the agent asks cloud to record on the deployment timeline.
	Events []Event `json:"events,omitempty"`
	// BackupState is the managed-DB backup topology: "" (backups off), "local" (repo1 only), or
	// "local+offsite" (repo1 + encrypted repo2 on S3). Cloud surfaces it in the admin UI.
	BackupState string `json:"backupState,omitempty"`
}
