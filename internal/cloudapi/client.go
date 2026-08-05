package cloudapi

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	agentv1 "github.com/vritti-ai-platforms/vritti-application-agent/gen/agent/v1"
	"github.com/vritti-ai-platforms/vritti-application-agent/gen/agent/v1/agentv1connect"
)

// Signer produces a base64 Ed25519 signature over a message (the agent's signing key).
type Signer interface {
	Sign(msg []byte) string
	SigningPublicB64() string
}

// Client is a Connect (gRPC-compatible) client to cloud-server. Every call carries the agent credential
// plus an Ed25519 signature over `<unix-seconds>.<deploymentId>` as request metadata, so cloud can verify
// both that the request came from this enrolled agent and that it is fresh (replay window). Server-streaming
// (Subscribe) rides HTTP/1.1, so it works through Cloudflare (which does not reliably proxy raw gRPC bidi).
type Client struct {
	deploymentID string
	signer       Signer
	svc          agentv1connect.AgentServiceClient

	credential string // set after enroll, read by the auth interceptor on every subsequent call
}

// New builds a cloud client for one deployment. No client-level timeout — the Subscribe stream is
// long-lived; unary calls carry their own context deadlines.
func New(baseURL, deploymentID string, signer Signer) *Client {
	c := &Client{deploymentID: deploymentID, signer: signer}
	c.svc = agentv1connect.NewAgentServiceClient(
		http.DefaultClient,
		strings.TrimRight(baseURL, "/"),
		connect.WithInterceptors(&authInterceptor{c: c}),
	)
	return c
}

// SetCredential installs the bearer credential returned from enrollment.
func (c *Client) SetCredential(cred string) { c.credential = cred }

// Enroll performs the one-time enrollment handshake and returns the deployment public key plus the
// connectivity nonce/signature for the caller to verify.
func (c *Client) Enroll(ctx context.Context, token, agentVersion string) (*EnrollResponse, error) {
	return c.enroll(ctx, token, "", agentVersion)
}

// EnrollWithSealing is like Enroll but also registers the agent's sealing public key.
func (c *Client) EnrollWithSealing(ctx context.Context, token, sealingPub, agentVersion string) (*EnrollResponse, error) {
	return c.enroll(ctx, token, sealingPub, agentVersion)
}

func (c *Client) enroll(ctx context.Context, token, sealingPub, agentVersion string) (*EnrollResponse, error) {
	resp, err := c.svc.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		DeploymentId:  c.deploymentID,
		EnrollToken:   token,
		SigningPubKey: c.signer.SigningPublicB64(),
		SealingPubKey: sealingPub,
		AgentVersion:  agentVersion,
	}))
	if err != nil {
		return nil, err
	}
	return &EnrollResponse{
		AgentCredential:  resp.Msg.AgentCredential,
		DeploymentPubKey: resp.Msg.DeploymentPubKey,
		Nonce:            resp.Msg.Nonce,
		NonceSignature:   resp.Msg.NonceSignature,
	}, nil
}

// ReportStatus pushes a heartbeat with conditions, per-service state, host metrics, certs, and events.
func (c *Client) ReportStatus(ctx context.Context, report StatusReport) error {
	_, err := c.svc.ReportStatus(ctx, connect.NewRequest(toProtoStatusReport(report)))
	return err
}

// LogLineData is one tailed log line to push (the target is passed to PushLogs, so it's not repeated here).
type LogLineData struct {
	Stream string // stdout | stderr
	Ts     string // RFC3339 timestamp from the docker log line
	Line   string
}

// PushLogs POSTs a batch of tailed lines for one container target. Unary, not a client-stream: Cloudflare
// buffers request bodies, so a streamed upload never reaches the origin live — a unary batch does. The agent
// flushes a batch every ~250ms or when it fills while a browser is watching.
func (c *Client) PushLogs(ctx context.Context, target string, lines []LogLineData) error {
	batch := make([]*agentv1.LogLine, len(lines))
	for i, l := range lines {
		batch[i] = &agentv1.LogLine{Target: target, Stream: l.Stream, Ts: l.Ts, Line: l.Line}
	}
	_, err := c.svc.PushLogs(ctx, connect.NewRequest(&agentv1.LogBatch{Lines: batch}))
	return err
}

// Subscribe opens the cloud->agent push stream. Cloud immediately sends the current signed desired-state,
// then a new one on every generation bump (or a Command / KeepAlive). knownGeneration lets cloud skip an
// immediate re-push when the agent is already current.
func (c *Client) Subscribe(ctx context.Context, knownGeneration int64) (*Subscription, error) {
	stream, err := c.svc.Subscribe(ctx, connect.NewRequest(&agentv1.SubscribeRequest{
		DeploymentId:    c.deploymentID,
		KnownGeneration: knownGeneration,
	}))
	if err != nil {
		return nil, err
	}
	return &Subscription{stream: stream}, nil
}

// Subscription is an open Subscribe server-stream. Call Receive until it returns a non-nil error.
type Subscription struct {
	stream *connect.ServerStreamForClient[agentv1.ServerMessage]
}

// ServerEvent is one decoded frame from the Subscribe stream — exactly one field is set.
type ServerEvent struct {
	DesiredState *SignedDesiredState // a desired-state push (verify + reconcile)
	Command      *Command            // an out-of-band instruction (force recheck, start/stop logs)
	KeepAlive    bool                // liveness frame only (keeps the CF-proxied stream from idling out)
}

// Command mirrors the agent-actionable subset of the wire Command oneof (pushed on the Subscribe stream).
type Command struct {
	ForceRecheck  bool
	RequestStatus bool
	StartLogs     *StartLogs
	StopLogs      *StopLogs
}

// StartLogs asks the agent to tail one container ("agent" or a service name) and stream its lines up.
type StartLogs struct {
	Target    string
	TailLines int32
	Since     string
}

// StopLogs asks the agent to stop tailing a container.
type StopLogs struct {
	Target string
}

// Receive blocks for the next server frame. Returns io.EOF on a clean stream close, or the stream error.
func (s *Subscription) Receive() (*ServerEvent, error) {
	if !s.stream.Receive() {
		if err := s.stream.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	switch m := s.stream.Msg().Msg.(type) {
	case *agentv1.ServerMessage_DesiredState:
		return &ServerEvent{DesiredState: &SignedDesiredState{
			PayloadB64: m.DesiredState.PayloadB64,
			Signature:  m.DesiredState.Signature,
		}}, nil
	case *agentv1.ServerMessage_Command:
		return &ServerEvent{Command: mapCommand(m.Command)}, nil
	case *agentv1.ServerMessage_KeepAlive:
		return &ServerEvent{KeepAlive: true}, nil
	default:
		return &ServerEvent{}, nil
	}
}

// Close releases the stream.
func (s *Subscription) Close() error { return s.stream.Close() }

func mapCommand(c *agentv1.Command) *Command {
	switch k := c.Kind.(type) {
	case *agentv1.Command_ForceRecheck:
		return &Command{ForceRecheck: true}
	case *agentv1.Command_RequestStatus:
		return &Command{RequestStatus: true}
	case *agentv1.Command_StartLogs:
		return &Command{StartLogs: &StartLogs{Target: k.StartLogs.Target, TailLines: k.StartLogs.TailLines, Since: k.StartLogs.Since}}
	case *agentv1.Command_StopLogs:
		return &Command{StopLogs: &StopLogs{Target: k.StopLogs.Target}}
	default:
		return &Command{}
	}
}

// toProtoStatusReport maps the internal StatusReport to its proto wire form (none of it is content-signed).
func toProtoStatusReport(r StatusReport) *agentv1.StatusReport {
	out := &agentv1.StatusReport{DeploymentId: r.DeploymentID, Generation: r.Generation}
	for _, c := range r.Conditions {
		out.Conditions = append(out.Conditions, &agentv1.Condition{
			Type: c.Type, Status: c.Status, Reason: c.Reason, Message: c.Message, Component: c.Component, Since: c.Since,
		})
	}
	for _, s := range r.Services {
		out.Services = append(out.Services, &agentv1.ServiceStatus{
			Component: s.Component, Service: s.Service, Name: s.Name, State: s.State, Health: s.Health,
			CpuPercent: s.CPUPercent, MemoryBytes: s.MemoryBytes,
		})
	}
	if r.Host != nil {
		out.Host = &agentv1.HostMetrics{
			CpuPercent: r.Host.CPUPercent, MemTotalBytes: r.Host.MemTotalBytes, MemUsedBytes: r.Host.MemUsedBytes,
			DiskTotalBytes: r.Host.DiskTotalBytes, DiskUsedBytes: r.Host.DiskUsedBytes,
		}
	}
	for _, c := range r.Certificates {
		out.Certificates = append(out.Certificates, &agentv1.CertReport{Host: c.Host, NotAfter: c.NotAfter, IssuedAt: c.IssuedAt})
	}
	if r.Delegation != nil {
		out.Delegation = &agentv1.AcmeChallengeDelegation{
			Name: r.Delegation.Name, Target: r.Delegation.Target, Zone: r.Delegation.Zone,
			Nameserver: r.Delegation.Nameserver, ServerIp: r.Delegation.ServerIP,
		}
	}
	for _, e := range r.Events {
		out.Events = append(out.Events, &agentv1.Event{Level: e.Level, Component: e.Component, Reason: e.Reason, Message: e.Message})
	}
	return out
}

// authInterceptor attaches the 5 agent auth headers (signing `<ts>.<deploymentId>`) to every unary call
// and to the Subscribe stream open, mirroring the cloud-server Connect auth interceptor.
type authInterceptor struct{ c *Client }

func (a *authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		a.setAuthHeaders(req.Header())
		return next(ctx, req)
	}
}

func (a *authInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		a.setAuthHeaders(conn.RequestHeader())
		return conn
	}
}

// WrapStreamingHandler is a no-op — this interceptor is client-side only.
func (a *authInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

func (a *authInterceptor) setAuthHeaders(h http.Header) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	signed := ts + "." + a.c.deploymentID
	h.Set("X-Vritti-Deployment", a.c.deploymentID)
	h.Set("X-Vritti-Agent-Key", a.c.signer.SigningPublicB64())
	h.Set("X-Vritti-Timestamp", ts)
	h.Set("X-Vritti-Signature", a.c.signer.Sign([]byte(signed)))
	if a.c.credential != "" {
		h.Set("Authorization", "Bearer "+a.c.credential)
	}
}
