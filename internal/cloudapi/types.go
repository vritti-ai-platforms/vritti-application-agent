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

// AddOns are the truly optional stack features toggled per deployment. nginx is NOT here — it is a
// core service governed by DesiredState.Edge.
type AddOns struct {
	PgBackRest      bool `json:"pgBackRest"`      // premium; only meaningful with ModeManaged
	BackupRetention int  `json:"backupRetention"` // pgBackRest full backups kept (repo*-retention-full); <1 falls back to 4
	Gitea           bool `json:"gitea"`
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

// DesiredState is what cloud wants running; the agent reconciles toward it. Cloud SIGNS this
// with the deployment private key and the agent verifies with the deployment public key.
type DesiredState struct {
	Generation     int64             `json:"generation"` // monotonic; agent skips reconcile if unchanged
	DeploymentID   string            `json:"deploymentId"`
	Version        string            `json:"version"` // pinned catalog/app version reference
	Mode           DBMode            `json:"mode"`
	Edge           EdgeMode          `json:"edge"`        // managed = agent runs nginx+certbot; external = BYO edge
	BaseDomain     string            `json:"baseDomain"`  // e.g. dev.vrittiai.com / apw1.vrittiai.com
	Domains        []DomainRoute     `json:"domains"`     // hosts the managed edge serves + certs (ignored when Edge=external)
	AcmeEmail      string            `json:"acmeEmail"`   // Let's Encrypt registration email (cloud-owned)
	AcmeStaging    bool              `json:"acmeStaging"` // use the LE staging CA (avoids rate limits while testing)
	Images         Images            `json:"images"`
	WebBundles     []WebBundle       `json:"webBundles"` // static web artifacts the managed edge serves off *.<base>
	AddOns         AddOns            `json:"addOns"`
	SecretProvider *SecretProvider   `json:"secretProvider"` // per-deployment secret store (cloud-provided); nil = none
	Config         map[string]string `json:"config"`         // plaintext non-secret config (R2 bucket names, tunables)
	SealedSecrets  map[string]string `json:"sealedSecrets"`  // name -> base64 sealed ciphertext (agent decrypts)
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

// ContainerReport is a single service's status in a heartbeat.
type ContainerReport struct {
	Service     string  `json:"service"`
	Name        string  `json:"name"`
	State       string  `json:"state"`
	Health      string  `json:"health"`
	CPUPercent  float64 `json:"cpuPercent"`
	MemoryBytes uint64  `json:"memoryBytes"`
}

// StatusReport is the periodic heartbeat the agent pushes to cloud.
type StatusReport struct {
	DeploymentID string            `json:"deploymentId"`
	Generation   int64             `json:"generation"` // desired-state generation currently applied
	Phase        string            `json:"phase"`      // enrolled | reconciling | ready | error
	Message      string            `json:"message"`
	Containers   []ContainerReport `json:"containers"`
	// GiteaProvisioned tells core-server (via cloud) the Gitea user+PAT are stored.
	GiteaProvisioned bool `json:"giteaProvisioned"`
	// Certificates report each managed-edge cert's expiry so cloud can track/alert (system of record).
	Certificates []CertReport `json:"certificates"`
	// AcmeDelegation, when non-nil, is the one-time CNAME the operator must add before the wildcard
	// cert can be issued (surfaced in the wizard's DNS-Delegation step).
	AcmeDelegation *AcmeChallengeDelegation `json:"acmeDelegation,omitempty"`
}
