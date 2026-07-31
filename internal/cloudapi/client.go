package cloudapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Signer produces a base64 Ed25519 signature over a message (the agent's signing key).
type Signer interface {
	Sign(msg []byte) string
	SigningPublicB64() string
}

// Client is a signed HTTP client to cloud-server. Every authenticated request carries the
// agent credential plus an Ed25519 signature over the body, so cloud can verify both that
// the request came from this enrolled agent and that the body was not tampered with.
type Client struct {
	baseURL      string
	deploymentID string
	http         *http.Client
	signer       Signer

	credential string // set after enroll
}

// New builds a cloud client for one deployment.
func New(baseURL, deploymentID string, signer Signer) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		deploymentID: deploymentID,
		signer:       signer,
		http:         &http.Client{Timeout: 30 * time.Second},
	}
}

// SetCredential installs the bearer credential returned from enrollment.
func (c *Client) SetCredential(cred string) { c.credential = cred }

// Enroll performs the one-time enrollment handshake and returns the deployment public key
// plus the connectivity nonce/signature for the caller to verify.
func (c *Client) Enroll(ctx context.Context, token, agentVersion string) (*EnrollResponse, error) {
	body := EnrollRequest{
		DeploymentID:  c.deploymentID,
		EnrollToken:   token,
		SigningPubKey: c.signer.SigningPublicB64(),
		AgentVersion:  agentVersion,
	}
	// SealingPubKey is filled by the caller-provided signer type if available; kept explicit below.
	var resp EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/agent/enroll", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EnrollWithSealing is like Enroll but also registers the agent's sealing public key.
func (c *Client) EnrollWithSealing(ctx context.Context, token, sealingPub, agentVersion string) (*EnrollResponse, error) {
	body := EnrollRequest{
		DeploymentID:  c.deploymentID,
		EnrollToken:   token,
		SigningPubKey: c.signer.SigningPublicB64(),
		SealingPubKey: sealingPub,
		AgentVersion:  agentVersion,
	}
	var resp EnrollResponse
	if err := c.do(ctx, http.MethodPost, "/agent/enroll", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// FetchDesiredState pulls the current signed desired-state for this deployment.
func (c *Client) FetchDesiredState(ctx context.Context) (*SignedDesiredState, error) {
	var resp SignedDesiredState
	path := fmt.Sprintf("/agent/deployments/%s/desired-state", c.deploymentID)
	if err := c.do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReportStatus pushes a heartbeat with container states and lifecycle phase.
func (c *Client) ReportStatus(ctx context.Context, report StatusReport) error {
	path := fmt.Sprintf("/agent/deployments/%s/status", c.deploymentID)
	return c.do(ctx, http.MethodPost, path, report, nil)
}

// do issues a signed JSON request and decodes the JSON response into out (may be nil).
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var payload []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		payload = b
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vritti-Deployment", c.deploymentID)
	if c.credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.credential)
	}
	// Sign the body (empty body still signs the empty string) so cloud can verify integrity.
	req.Header.Set("X-Vritti-Agent-Key", c.signer.SigningPublicB64())
	req.Header.Set("X-Vritti-Signature", c.signer.Sign(payload))

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloud %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if out != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, out)
	}
	return nil
}
