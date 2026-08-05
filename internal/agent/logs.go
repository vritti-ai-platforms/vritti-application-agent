package agent

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// logFlushInterval / logBatchMax bound how the agent batches tailed lines before POSTing them via PushLogs:
// flush at least this often (keeps latency low) and whenever a batch fills (keeps requests bounded).
const (
	logFlushInterval = 250 * time.Millisecond
	logBatchMax      = 200
)

// logManager tails container logs on demand and pushes them to cloud. Each active target ("agent" or a
// service) gets its own independent tail goroutine; StopLogs cancels it. Lines are batched and POSTed via the
// unary PushLogs (NOT a client-stream — Cloudflare buffers request bodies). Cloud ref-counts browser viewers
// and only asks the agent to tail while at least one is watching, so a tail exists only while someone looks.
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

// run resolves the container, tails it, and pushes batched demuxed lines up via PushLogs until ctx is cancelled.
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

	lines := make(chan dockerx.LogLine, 128)
	go func() {
		_ = m.dx.FollowLogs(ctx, id, tailLines, since, lines)
		close(lines)
	}()

	batch := make([]cloudapi.LogLineData, 0, logBatchMax)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Use baseCtx, not ctx: on StopLogs (ctx cancelled) we still want the final batch to land.
		if err := m.cloud.PushLogs(m.baseCtx, target, batch); err != nil {
			m.log.Warn("push logs failed", "target", target, "err", err)
		}
		batch = batch[:0]
	}
	defer flush()

	ticker := time.NewTicker(logFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return
			}
			batch = append(batch, cloudapi.LogLineData{Stream: line.Stream, Ts: line.Ts, Line: line.Line})
			if len(batch) >= logBatchMax {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			return
		}
	}
}
