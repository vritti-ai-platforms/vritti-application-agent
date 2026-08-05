package agent

import (
	"context"
	"log/slog"
	"sync"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// logManager tails container logs on demand and streams them to cloud. Each active target ("agent" or a
// service) gets its own independent tail goroutine + StreamLogs client-stream; StopLogs cancels it. Cloud
// ref-counts browser viewers and only asks the agent to tail while at least one is watching, so a tail
// exists only while someone is looking.
type logManager struct {
	baseCtx context.Context
	dx      *dockerx.Client
	cloud   *cloudapi.Client
	log     *slog.Logger

	mu    sync.Mutex
	tails map[string]context.CancelFunc // target -> cancel
}

func newLogManager(ctx context.Context, dx *dockerx.Client, cloud *cloudapi.Client, log *slog.Logger) *logManager {
	return &logManager{baseCtx: ctx, dx: dx, cloud: cloud, log: log, tails: map[string]context.CancelFunc{}}
}

// start begins tailing target (idempotent — a second StartLogs for an already-tailed target is ignored).
func (m *logManager) start(target string, tailLines int, since string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tails[target]; ok {
		return
	}
	ctx, cancel := context.WithCancel(m.baseCtx)
	m.tails[target] = cancel
	go m.run(ctx, target, tailLines, since)
	m.log.Info("started log tail", "target", target)
}

// stop cancels the tail for target (if any).
func (m *logManager) stop(target string) {
	m.mu.Lock()
	cancel := m.tails[target]
	delete(m.tails, target)
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		m.log.Info("stopped log tail", "target", target)
	}
}

// run resolves the container, opens a StreamLogs stream, and forwards demuxed lines up until ctx is cancelled.
func (m *logManager) run(ctx context.Context, target string, tailLines int, since string) {
	defer func() {
		m.mu.Lock()
		delete(m.tails, target)
		m.mu.Unlock()
	}()

	id, err := m.dx.ResolveLogTarget(ctx, target)
	if err != nil {
		m.log.Warn("resolve log target", "target", target, "err", err)
		return
	}

	sender := m.cloud.OpenLogStream(ctx)
	defer func() { _ = sender.Close() }()

	lines := make(chan dockerx.LogLine, 128)
	go func() {
		_ = m.dx.FollowLogs(ctx, id, tailLines, since, lines)
		close(lines)
	}()

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return
			}
			if err := sender.Send(target, line.Stream, line.Ts, line.Line); err != nil {
				m.log.Warn("log stream send failed", "target", target, "err", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
