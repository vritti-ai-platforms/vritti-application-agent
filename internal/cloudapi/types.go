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

// AddOns are the optional stack features toggled per deployment.
type AddOns struct {
	PgBackRest bool `json:"pgBackRest"` // premium; only meaningful with ModeManaged
	Gitea      bool `json:"gitea"`
	Nginx      bool `json:"nginx"` // edge proxy on customer VMs (shared edge on vm1 handles dev)
}

// DesiredState is what cloud wants running; the agent reconciles toward it. Cloud SIGNS this
// with the deployment private key and the agent verifies with the deployment public key.
type DesiredState struct {
	Generation    int64             `json:"generation"` // monotonic; agent skips reconcile if unchanged
	DeploymentID  string            `json:"deploymentId"`
	Version       string            `json:"version"`    // pinned catalog/app version reference
	Mode          DBMode            `json:"mode"`
	BaseDomain    string            `json:"baseDomain"` // e.g. dev.vrittiai.com / apw1.vrittiai.com
	Images        Images            `json:"images"`
	AddOns        AddOns            `json:"addOns"`
	Config        map[string]string `json:"config"`        // plaintext non-secret config (R2 bucket names, tunables)
	SealedSecrets map[string]string `json:"sealedSecrets"` // name -> base64 sealed ciphertext (agent decrypts)
}

// SignedDesiredState wraps DesiredState with cloud's signature over the canonical payload bytes.
type SignedDesiredState struct {
	Payload   DesiredState `json:"payload"`
	PayloadB64 string      `json:"payloadB64"` // canonical JSON the signature is computed over
	Signature string      `json:"signature"`  // base64 Ed25519 signature by the deployment key
}

// EnrollRequest is sent once, presenting the one-time token and the agent's fresh public keys.
type EnrollRequest struct {
	DeploymentID   string `json:"deploymentId"`
	EnrollToken    string `json:"enrollToken"`
	SigningPubKey  string `json:"signingPubKey"` // agent Ed25519 public (agent→cloud auth)
	SealingPubKey  string `json:"sealingPubKey"` // agent X25519 public (seal target)
	AgentVersion   string `json:"agentVersion"`
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
	DeploymentID    string            `json:"deploymentId"`
	Generation      int64             `json:"generation"` // desired-state generation currently applied
	Phase           string            `json:"phase"`      // enrolled | reconciling | ready | error
	Message         string            `json:"message"`
	Containers      []ContainerReport `json:"containers"`
	// GiteaProvisioned tells core-server (via cloud) the Gitea user+PAT are stored.
	GiteaProvisioned bool `json:"giteaProvisioned"`
}
