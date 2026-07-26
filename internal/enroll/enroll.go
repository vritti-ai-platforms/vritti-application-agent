// Package enroll runs the one-time enrollment handshake (steps iii–iv of the flow):
// the agent presents its one-time token + fresh public keys, cloud returns the deployment
// public key + a signed nonce, and the agent verifies that signature to prove it is talking
// to the genuine cloud/deployment before trusting anything it later signs.
package enroll

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/agentcrypto"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/config"
)

// Run returns a completed enrollment, performing the handshake only on first boot.
func Run(ctx context.Context, client *cloudapi.Client, keys *agentcrypto.Keys, cfg *config.Config, agentVersion string) (*cloudapi.Enrollment, error) {
	// Already enrolled? Reuse the cached credential + deployment public key.
	if data, err := os.ReadFile(cfg.EnrollmentPath()); err == nil {
		var e cloudapi.Enrollment
		if json.Unmarshal(data, &e) == nil && e.AgentCredential != "" {
			return &e, nil
		}
	}

	if cfg.EnrollToken == "" {
		return nil, fmt.Errorf("not enrolled and VRITTI_ENROLL_TOKEN is empty (paste the one-time token from admin)")
	}

	resp, err := client.EnrollWithSealing(ctx, cfg.EnrollToken, keys.SealingPublicB64(), agentVersion)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}

	// Connectivity test: the nonce must be signed by the deployment private key held by cloud.
	if !agentcrypto.VerifyDeployment(resp.DeploymentPubKey, []byte(resp.Nonce), resp.NonceSignature) {
		return nil, fmt.Errorf("handshake failed: cloud's nonce signature did not verify against the deployment key")
	}

	e := &cloudapi.Enrollment{
		AgentCredential:  resp.AgentCredential,
		DeploymentPubKey: resp.DeploymentPubKey,
	}
	blob, _ := json.MarshalIndent(e, "", "  ")
	if err := os.WriteFile(cfg.EnrollmentPath(), blob, 0o600); err != nil {
		return nil, err
	}
	return e, nil
}
