// Package dockerx is a thin, opinionated wrapper over the Docker Engine SDK.
// The agent drives the Engine API directly — there is no docker-compose file.
// Every object the agent creates is tagged with the deployment label so the
// reconciler can list and prune exactly what it owns.
package dockerx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
)

// LabelDeployment tags every container/network the agent owns with the deployment id.
const LabelDeployment = "vritti.deployment"

// LabelSpecHash stores the hash of the RunSpec a container was created from so the
// reconciler can detect drift and recreate only when the desired spec actually changed.
const LabelSpecHash = "vritti.spec-hash"

// LabelService names the logical service (postgres, core-server, ...) within a deployment.
const LabelService = "vritti.service"

// Client wraps the Docker SDK client plus the deployment id it operates on.
type Client struct {
	api          *client.Client
	deploymentID string
}

// New negotiates an API version against the local Docker daemon.
func New(deploymentID string) (*Client, error) {
	api, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &Client{api: api, deploymentID: deploymentID}, nil
}

// Close releases the underlying HTTP transport.
func (c *Client) Close() error { return c.api.Close() }

// DiskUsage returns docker's on-disk footprint in bytes: deduped image layers, and the "containers" bucket
// (writable container layers + volumes + build cache). Mirrors `docker system df`. Our stack uses bind
// mounts, so volumes/build-cache are ~0 — they're folded into containers so nothing is missed.
func (c *Client) DiskUsage(ctx context.Context) (images, containers uint64, err error) {
	du, err := c.api.DiskUsage(ctx, types.DiskUsageOptions{})
	if err != nil {
		return 0, 0, err
	}
	if du.LayersSize > 0 {
		images = uint64(du.LayersSize)
	}
	var other int64
	for _, ct := range du.Containers {
		other += ct.SizeRw
	}
	for _, v := range du.Volumes {
		if v.UsageData != nil && v.UsageData.Size > 0 {
			other += v.UsageData.Size
		}
	}
	for _, bc := range du.BuildCache {
		other += bc.Size
	}
	if other > 0 {
		containers = uint64(other)
	}
	return images, containers, nil
}

// HealthSpec is a container-level healthcheck.
type HealthSpec struct {
	Test     []string
	Interval time.Duration
	Timeout  time.Duration
	Retries  int
	Start    time.Duration
}

// RunSpec is the declarative description of a single container the agent wants running.
type RunSpec struct {
	Name         string
	Image        string
	Env          []string
	Cmd          []string
	Binds        []string          // "hostPath:containerPath[:ro]"
	Ports        map[string]string // containerPort/proto -> hostPort ("" = published on all)
	ExposedPorts []string          // "port/proto" exposed but not published
	Network      string
	Service      string
	Labels       map[string]string
	Restart      bool
	MemLimit     int64
	ExtraHosts   []string
	Health       *HealthSpec
}

// EnsureNetwork creates the bridge network if it does not already exist.
func (c *Client) EnsureNetwork(ctx context.Context, name string) error {
	nets, err := c.api.NetworkList(ctx, network.ListOptions{
		Filters: filters.NewArgs(filters.Arg("name", name)),
	})
	if err != nil {
		return err
	}
	for _, n := range nets {
		if n.Name == name {
			return nil
		}
	}
	_, err = c.api.NetworkCreate(ctx, name, network.CreateOptions{
		Driver: "bridge",
		Labels: map[string]string{LabelDeployment: c.deploymentID},
	})
	return err
}

// EnsureVolume creates a named volume if absent (used only where a bind mount is not suitable).
func (c *Client) EnsureVolume(ctx context.Context, name string) error {
	_, err := c.api.VolumeCreate(ctx, volume.CreateOptions{
		Name:   name,
		Labels: map[string]string{LabelDeployment: c.deploymentID},
	})
	return err
}

// PullImage pulls a reference and drains the progress stream to completion. It attaches registry
// credentials resolved from the host Docker config (as written by `docker login`) when present, so
// private images pull without any store-specific auth baked into the agent; public images pull
// anonymously when no matching credential is found.
func (c *Client) PullImage(ctx context.Context, ref string) error {
	rc, err := c.api.ImagePull(ctx, ref, image.PullOptions{RegistryAuth: resolveRegistryAuth(ref)})
	if err != nil {
		return fmt.Errorf("pull %s: %w", ref, err)
	}
	defer rc.Close()
	_, err = io.Copy(io.Discard, rc)
	return err
}

// resolveRegistryAuth returns the base64 X-Registry-Auth header for ref's registry, read from the
// host Docker config (DOCKER_CONFIG or ~/.docker/config.json), or "" for an anonymous pull. This is
// generic: the agent reuses whatever registry the host is logged in to, with nothing registry- or
// operator-specific compiled in.
func resolveRegistryAuth(ref string) string {
	host, user, pass := RegistryCredential(ref)
	if user == "" && pass == "" {
		return ""
	}
	enc, err := registry.EncodeAuthConfig(registry.AuthConfig{
		Username:      user,
		Password:      pass,
		ServerAddress: host,
	})
	if err != nil {
		return ""
	}
	return enc
}

// RegistryCredential resolves the (host, username, password) for ref's registry from the host Docker
// config (DOCKER_CONFIG or ~/.docker/config.json). user/pass are "" when the host isn't logged in to
// that registry (anonymous). Shared by image pulls and the oras web-bundle pull so both reuse the one
// credential source the operator's `docker login` already established.
func RegistryCredential(ref string) (host, user, pass string) {
	host = registryHost(ref)

	cfgDir := os.Getenv("DOCKER_CONFIG")
	if cfgDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return host, "", ""
		}
		cfgDir = filepath.Join(home, ".docker")
	}
	raw, err := os.ReadFile(filepath.Join(cfgDir, "config.json"))
	if err != nil {
		return host, "", ""
	}

	var cfg struct {
		Auths map[string]struct {
			Auth     string `json:"auth"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return host, "", ""
	}

	entry, ok := cfg.Auths[host]
	if !ok {
		return host, "", ""
	}
	user, pass = entry.Username, entry.Password
	if entry.Auth != "" {
		if dec, err := base64.StdEncoding.DecodeString(entry.Auth); err == nil {
			if i := strings.IndexByte(string(dec), ':'); i >= 0 {
				user, pass = string(dec[:i]), string(dec[i+1:])
			}
		}
	}
	return host, user, pass
}

// registryHost extracts the registry hostname from an image reference, defaulting to Docker Hub.
// The registry is the first path segment only when it looks like a host (contains "." or ":", or is
// "localhost"); otherwise the reference is a Docker Hub library/user image.
func registryHost(ref string) string {
	i := strings.IndexByte(ref, '/')
	if i < 0 {
		return "docker.io"
	}
	first := ref[:i]
	if first == "localhost" || strings.ContainsAny(first, ".:") {
		return first
	}
	return "docker.io"
}

// containerByName returns the container id for a name, and whether it exists.
func (c *Client) containerByName(ctx context.Context, name string) (string, bool, error) {
	list, err := c.api.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("name", "^/"+name+"$")),
	})
	if err != nil {
		return "", false, err
	}
	if len(list) == 0 {
		return "", false, nil
	}
	return list[0].ID, true, nil
}

// SpecHash reads the recorded spec hash label of a running container ("" if absent/missing).
func (c *Client) SpecHash(ctx context.Context, name string) (string, error) {
	id, ok, err := c.containerByName(ctx, name)
	if err != nil || !ok {
		return "", err
	}
	insp, err := c.api.ContainerInspect(ctx, id)
	if err != nil {
		return "", err
	}
	return insp.Config.Labels[LabelSpecHash], nil
}

// Remove force-removes a container by name (no-op if it does not exist).
func (c *Client) Remove(ctx context.Context, name string) error {
	id, ok, err := c.containerByName(ctx, name)
	if err != nil || !ok {
		return err
	}
	return c.api.ContainerRemove(ctx, id, container.RemoveOptions{Force: true})
}

// Restart restarts a container by name.
func (c *Client) Restart(ctx context.Context, name string) error {
	id, ok, err := c.containerByName(ctx, name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("container %s not found", name)
	}
	return c.api.ContainerRestart(ctx, id, container.StopOptions{})
}

// EnsureStarted starts the named container if it exists but is not running, and reports whether it had to
// start it. No-op (started=false) when it's already running or absent. Lets the reconciler self-heal a
// crashed or manually-stopped service whose spec is otherwise unchanged (RestartPolicyUnlessStopped means
// Docker won't bring a manual `docker stop` back on its own).
func (c *Client) EnsureStarted(ctx context.Context, name string) (bool, error) {
	id, ok, err := c.containerByName(ctx, name)
	if err != nil || !ok {
		return false, err
	}
	insp, err := c.api.ContainerInspect(ctx, id)
	if err != nil {
		return false, err
	}
	if insp.State != nil && insp.State.Running {
		return false, nil
	}
	if err := c.api.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		return false, fmt.Errorf("start %s: %w", name, err)
	}
	return true, nil
}

// create builds the container from a RunSpec and returns its id (does not start it).
func (c *Client) create(ctx context.Context, spec RunSpec) (string, error) {
	labels := map[string]string{
		LabelDeployment: c.deploymentID,
		LabelService:    spec.Service,
	}
	maps.Copy(labels, spec.Labels)

	exposed := nat.PortSet{}
	bindings := nat.PortMap{}
	for _, p := range spec.ExposedPorts {
		exposed[nat.Port(p)] = struct{}{}
	}
	for cport, hport := range spec.Ports {
		np := nat.Port(cport)
		exposed[np] = struct{}{}
		bindings[np] = []nat.PortBinding{{HostIP: "0.0.0.0", HostPort: hport}}
	}

	cfg := &container.Config{
		Image:        spec.Image,
		Env:          spec.Env,
		Cmd:          spec.Cmd,
		Labels:       labels,
		ExposedPorts: exposed,
	}
	if spec.Health != nil {
		cfg.Healthcheck = &container.HealthConfig{
			Test:        spec.Health.Test,
			Interval:    spec.Health.Interval,
			Timeout:     spec.Health.Timeout,
			Retries:     spec.Health.Retries,
			StartPeriod: spec.Health.Start,
		}
	}

	host := &container.HostConfig{
		Binds:        spec.Binds,
		PortBindings: bindings,
		ExtraHosts:   spec.ExtraHosts,
		Resources:    container.Resources{Memory: spec.MemLimit},
		LogConfig: container.LogConfig{
			Type:   "json-file",
			Config: map[string]string{"max-size": "10m", "max-file": "3"},
		},
	}
	if spec.Restart {
		host.RestartPolicy = container.RestartPolicy{Name: container.RestartPolicyUnlessStopped}
	}

	netCfg := &network.NetworkingConfig{}
	if spec.Network != "" {
		netCfg.EndpointsConfig = map[string]*network.EndpointSettings{spec.Network: {}}
	}

	created, err := c.api.ContainerCreate(ctx, cfg, host, netCfg, nil, spec.Name)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", spec.Name, err)
	}
	return created.ID, nil
}

// Run removes any existing container of the same name and creates+starts a fresh one.
func (c *Client) Run(ctx context.Context, spec RunSpec) error {
	if err := c.Remove(ctx, spec.Name); err != nil {
		return err
	}
	id, err := c.create(ctx, spec)
	if err != nil {
		return err
	}
	return c.api.ContainerStart(ctx, id, container.StartOptions{})
}

// RunToCompletion runs a one-shot container (migrations, backups), waits for exit,
// and returns the exit code together with the captured logs.
func (c *Client) RunToCompletion(ctx context.Context, spec RunSpec) (int, string, error) {
	if err := c.Remove(ctx, spec.Name); err != nil {
		return -1, "", err
	}
	id, err := c.create(ctx, spec)
	if err != nil {
		return -1, "", err
	}
	defer c.api.ContainerRemove(ctx, id, container.RemoveOptions{Force: true})

	if err := c.api.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		return -1, "", err
	}
	waitCh, errCh := c.api.ContainerWait(ctx, id, container.WaitConditionNotRunning)
	var code int
	select {
	case err := <-errCh:
		if err != nil {
			return -1, "", err
		}
	case st := <-waitCh:
		code = int(st.StatusCode)
	}
	logs := c.readLogs(ctx, id, "all")
	return code, logs, nil
}

// Logs returns the last `tail` lines of a container's combined stdout/stderr.
func (c *Client) Logs(ctx context.Context, name, tail string) (string, error) {
	id, ok, err := c.containerByName(ctx, name)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("container %s not found", name)
	}
	return c.readLogs(ctx, id, tail), nil
}

// readLogs demultiplexes the Docker log stream into a plain string.
func (c *Client) readLogs(ctx context.Context, id, tail string) string {
	rc, err := c.api.ContainerLogs(ctx, id, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
	})
	if err != nil {
		return ""
	}
	defer rc.Close()
	var out bytes.Buffer
	_, _ = stdcopy.StdCopy(&out, &out, rc)
	return out.String()
}

// LogTargetAgent is the reserved log target for the agent's own container.
const LogTargetAgent = "agent"

// LogLine is one demuxed, timestamped container log line.
type LogLine struct {
	Stream string // "stdout" | "stderr"
	Ts     string // RFC3339 timestamp from the docker log stream
	Line   string
}

// ResolveLogTarget maps a target key to a tailable container id: "agent" is the agent's own container
// (its hostname is the container id inside a container), any other value is an owned service by its label.
func (c *Client) ResolveLogTarget(ctx context.Context, target string) (string, error) {
	if target == LogTargetAgent {
		return os.Hostname()
	}
	list, err := c.api.ContainerList(ctx, container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label", LabelDeployment+"="+c.deploymentID),
			filters.Arg("label", LabelService+"="+target),
		),
	})
	if err != nil {
		return "", err
	}
	if len(list) == 0 {
		return "", fmt.Errorf("no container for service %q", target)
	}
	return list[0].ID, nil
}

// FollowLogs tails a container, streaming demuxed lines to out until ctx is cancelled. tailLines is the
// initial backlog (<=0 = all); since is an optional RFC3339 lower bound. Timestamps are split off each line.
func (c *Client) FollowLogs(ctx context.Context, containerID string, tailLines int, since string, out chan<- LogLine) error {
	tail := "all"
	if tailLines > 0 {
		tail = strconv.Itoa(tailLines)
	}
	rc, err := c.api.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Timestamps: true,
		Tail:       tail,
		Since:      since,
	})
	if err != nil {
		return err
	}
	defer rc.Close()

	// Demux stdout/stderr into two pipes so each line keeps its stream tag; StdCopy runs until rc closes.
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	go func() {
		_, _ = stdcopy.StdCopy(stdoutW, stderrW, rc)
		_ = stdoutW.Close()
		_ = stderrW.Close()
	}()

	var wg sync.WaitGroup
	scan := func(r io.Reader, stream string) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			ts, line := splitLogTimestamp(sc.Text())
			select {
			case out <- LogLine{Stream: stream, Ts: ts, Line: line}:
			case <-ctx.Done():
				return
			}
		}
	}
	wg.Add(2)
	go scan(stdoutR, "stdout")
	go scan(stderrR, "stderr")

	<-ctx.Done()
	_ = rc.Close() // unblock StdCopy so the pipes close and the scanners drain
	wg.Wait()
	return nil
}

// splitLogTimestamp splits Docker's "<RFC3339Nano> <content>" prefix off a timestamped log line.
func splitLogTimestamp(s string) (ts, line string) {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

// StatsSample is a point-in-time resource reading for one container.
type StatsSample struct {
	Service     string  `json:"service"`
	Name        string  `json:"name"`
	CPUPercent  float64 `json:"cpuPercent"`
	MemoryBytes uint64  `json:"memoryBytes"`
	MemoryLimit uint64  `json:"memoryLimit"`
	MemPercent  float64 `json:"memPercent"`
}

// rawStats is a minimal projection of the Engine stats JSON (version-stable subset).
type rawStats struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs  uint64 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

// Stats reads a single (non-streaming) resource sample for a container by name.
func (c *Client) Stats(ctx context.Context, name string) (StatsSample, error) {
	id, ok, err := c.containerByName(ctx, name)
	if err != nil {
		return StatsSample{}, err
	}
	if !ok {
		return StatsSample{}, fmt.Errorf("container %s not found", name)
	}
	resp, err := c.api.ContainerStats(ctx, id, false)
	if err != nil {
		return StatsSample{}, err
	}
	defer resp.Body.Close()

	var raw rawStats
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return StatsSample{}, err
	}

	// Working-set memory = usage minus reclaimable page cache (matches `docker stats`).
	mem := raw.MemoryStats.Usage
	if cache, ok := raw.MemoryStats.Stats["inactive_file"]; ok && cache < mem {
		mem -= cache
	}
	sample := StatsSample{
		Name:        strings.TrimPrefix(name, "/"),
		MemoryBytes: mem,
		MemoryLimit: raw.MemoryStats.Limit,
	}
	if raw.MemoryStats.Limit > 0 {
		sample.MemPercent = float64(mem) / float64(raw.MemoryStats.Limit) * 100
	}
	cpuDelta := float64(raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(raw.CPUStats.SystemUsage - raw.PreCPUStats.SystemUsage)
	if sysDelta > 0 && cpuDelta > 0 {
		cpus := float64(raw.CPUStats.OnlineCPUs)
		if cpus == 0 {
			cpus = 1
		}
		sample.CPUPercent = (cpuDelta / sysDelta) * cpus * 100
	}
	return sample, nil
}

// ContainerStatus is the reconciler-visible state of one owned container.
type ContainerStatus struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Health  string `json:"health"`
	Image   string `json:"image"`
}

// List returns every container the agent owns for this deployment.
func (c *Client) List(ctx context.Context) ([]ContainerStatus, error) {
	list, err := c.api.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("label", LabelDeployment+"="+c.deploymentID)),
	})
	if err != nil {
		return nil, err
	}
	out := make([]ContainerStatus, 0, len(list))
	for _, ct := range list {
		name := ""
		if len(ct.Names) > 0 {
			name = strings.TrimPrefix(ct.Names[0], "/")
		}
		cs := ContainerStatus{
			Service: ct.Labels[LabelService],
			Name:    name,
			State:   ct.State,
			Status:  ct.Status,
			Image:   ct.Image,
		}
		if insp, err := c.api.ContainerInspect(ctx, ct.ID); err == nil && insp.State != nil && insp.State.Health != nil {
			cs.Health = insp.State.Health.Status
		}
		out = append(out, cs)
	}
	return out, nil
}

// ownedNames returns the set of container names the agent currently owns.
func (c *Client) ownedNames(ctx context.Context) (map[string]bool, error) {
	list, err := c.List(ctx)
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(list))
	for _, ct := range list {
		names[ct.Name] = true
	}
	return names, nil
}

// PruneExcept removes owned containers whose names are not in `keep`.
func (c *Client) PruneExcept(ctx context.Context, keep map[string]bool) error {
	owned, err := c.ownedNames(ctx)
	if err != nil {
		return err
	}
	for name := range owned {
		if !keep[name] {
			if err := c.Remove(ctx, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// Exec runs a command inside a running container and returns its exit code + combined output.
func (c *Client) Exec(ctx context.Context, name string, cmd []string) (int, string, error) {
	id, ok, err := c.containerByName(ctx, name)
	if err != nil {
		return -1, "", err
	}
	if !ok {
		return -1, "", fmt.Errorf("container %s not found", name)
	}
	created, err := c.api.ContainerExecCreate(ctx, id, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return -1, "", err
	}
	attach, err := c.api.ContainerExecAttach(ctx, created.ID, container.ExecAttachOptions{})
	if err != nil {
		return -1, "", err
	}
	defer attach.Close()

	var out bytes.Buffer
	_, _ = stdcopy.StdCopy(&out, &out, attach.Reader)

	insp, err := c.api.ContainerExecInspect(ctx, created.ID)
	if err != nil {
		return -1, out.String(), err
	}
	return insp.ExitCode, out.String(), nil
}

// ExecInput is Exec plus a stdin stream and extra env. It attaches stdin and writes `stdin` to the
// process before reading its output, so callers can pipe data (e.g. SQL to `psql -f -`) verbatim
// instead of shell-escaping it into the command — which mangles newlines and risks quoting bugs.
func (c *Client) ExecInput(ctx context.Context, name string, cmd, env []string, stdin string) (int, string, error) {
	id, ok, err := c.containerByName(ctx, name)
	if err != nil {
		return -1, "", err
	}
	if !ok {
		return -1, "", fmt.Errorf("container %s not found", name)
	}
	created, err := c.api.ContainerExecCreate(ctx, id, container.ExecOptions{
		Cmd:          cmd,
		Env:          env,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return -1, "", err
	}
	attach, err := c.api.ContainerExecAttach(ctx, created.ID, container.ExecAttachOptions{})
	if err != nil {
		return -1, "", err
	}
	defer attach.Close()

	if stdin != "" {
		_, _ = io.WriteString(attach.Conn, stdin)
	}
	_ = attach.CloseWrite() // EOF so psql stops reading and executes

	var out bytes.Buffer
	_, _ = stdcopy.StdCopy(&out, &out, attach.Reader)

	insp, err := c.api.ContainerExecInspect(ctx, created.ID)
	if err != nil {
		return -1, out.String(), err
	}
	return insp.ExitCode, out.String(), nil
}

// WaitHealthy blocks until the named container reports healthy (or the timeout elapses).
func (c *Client) WaitHealthy(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		id, ok, err := c.containerByName(ctx, name)
		if err != nil {
			return err
		}
		if ok {
			insp, err := c.api.ContainerInspect(ctx, id)
			if err == nil && insp.State != nil {
				if insp.State.Health == nil && insp.State.Running {
					return nil // no healthcheck defined; running is enough
				}
				if insp.State.Health != nil && insp.State.Health.Status == "healthy" {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("container %s not healthy within %s", name, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
