// Command agent is the vritti-application-agent entrypoint. It runs on the deployment VM
// (dev on vm1, prod on vm2, or a customer's own VM), enrolls with vritti-cloud, and reconciles
// the vritti-core stack toward the signed desired-state — driving the Docker Engine API
// directly, with no docker-compose file.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/agent"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a, err := agent.New(ctx, log)
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}

	log.Info("vritti-application-agent starting", "version", agent.Version)
	if err := a.Run(ctx); err != nil {
		log.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
	log.Info("agent stopped")
}
