package deploy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// certbotImage obtains + renews Let's Encrypt certs (HTTP-01 webroot). leDir is the on-host certbot
// config dir (certs under live/<host>/), shared read-only into nginx; leDir/www is the ACME webroot
// shared between certbot (writes challenges) and nginx (serves them).
const (
	certbotImage = "certbot/certbot:latest"
	leDir        = "letsencrypt"
)

// EdgeDirs are the host dirs the managed edge needs before nginx/certbot run.
func EdgeDirs(stackRoot string) []string {
	return []string{
		filepath.Join(stackRoot, "nginx", "conf.d"),
		filepath.Join(stackRoot, leDir, "www"),
		filepath.Join(stackRoot, "logs", "nginx"),
	}
}

// certLive is the host path to a domain's live cert directory.
func certLive(stackRoot, host string) string {
	return filepath.Join(stackRoot, leDir, "live", host)
}

// hasCert reports whether a live fullchain already exists for host.
func hasCert(stackRoot, host string) bool {
	_, err := os.Stat(filepath.Join(certLive(stackRoot, host), "fullchain.pem"))
	return err == nil
}

// RenderNginxConf builds the config: one HTTP server (ACME webroot + redirect to HTTPS) and one
// HTTPS server per domain that ALREADY has a cert, proxying to its upstream. It is cert-aware so it
// is valid both before first issuance (HTTP only, serving the challenge) and after (HTTPS appears).
func RenderNginxConf(stackRoot string, domains []cloudapi.DomainRoute) string {
	hosts := make([]string, 0, len(domains))
	for _, d := range domains {
		hosts = append(hosts, d.Host)
	}

	// Never emit `server_name ;` (nginx [emerg] invalid number of arguments) — fall back to the `_`
	// catch-all when there are no hosts. Callers shouldn't reach here with zero domains, but the
	// renderer stays valid regardless.
	serverName := strings.Join(hosts, " ")
	if serverName == "" {
		serverName = "_"
	}

	var b strings.Builder
	b.WriteString("server {\n  listen 80;\n  server_name " + serverName + ";\n")
	b.WriteString("  location /.well-known/acme-challenge/ { root /var/www/letsencrypt; }\n")
	b.WriteString("  location / { return 301 https://$host$request_uri; }\n}\n\n")

	for _, d := range domains {
		if !hasCert(stackRoot, d.Host) {
			continue
		}
		b.WriteString("server {\n  listen 443 ssl;\n  http2 on;\n  server_name " + d.Host + ";\n")
		b.WriteString("  ssl_certificate /etc/letsencrypt/live/" + d.Host + "/fullchain.pem;\n")
		b.WriteString("  ssl_certificate_key /etc/letsencrypt/live/" + d.Host + "/privkey.pem;\n")
		b.WriteString("  ssl_protocols TLSv1.2 TLSv1.3;\n  client_max_body_size 25m;\n")
		b.WriteString("  location / {\n")
		b.WriteString("    proxy_pass http://" + d.Upstream + ";\n")
		b.WriteString("    proxy_http_version 1.1;\n")
		b.WriteString("    proxy_set_header Host $host;\n")
		b.WriteString("    proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		b.WriteString("    proxy_set_header X-Forwarded-Proto $scheme;\n")
		b.WriteString("    proxy_set_header Upgrade $http_upgrade;\n")
		b.WriteString("    proxy_set_header Connection \"upgrade\";\n")
		b.WriteString("  }\n}\n\n")
	}
	return b.String()
}

// EnsureEdge brings up the managed nginx edge and returns the current cert reports: render conf,
// ensure nginx (serving :80 for the ACME challenge), obtain any missing certs, re-render + reload,
// then read each cert's validity window. The caller marks nginx as kept.
func EnsureEdge(ctx context.Context, dx *dockerx.Client, ds cloudapi.DesiredState, stackRoot string) ([]cloudapi.CertReport, error) {
	for _, dir := range EdgeDirs(stackRoot) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
	}
	// nginx workers (user `nginx`, non-root) serve the ACME webroot, so it must be world-traversable.
	// MkdirAll leaves it 0750/root and the worker fails with open() "(13: Permission denied)", which
	// Let's Encrypt sees as a 403 on the HTTP-01 challenge. certbot writes the challenge dir + files
	// world-readable itself, so 0755 on the webroot is all that's needed.
	if err := os.Chmod(filepath.Join(stackRoot, leDir, "www"), 0o755); err != nil {
		return nil, err
	}

	// Render (cert-aware) + start nginx so :80 answers the HTTP-01 challenge before certbot runs.
	changed, err := writeNginxConf(stackRoot, ds.Domains)
	if err != nil {
		return nil, err
	}
	if err := Apply(ctx, dx, NginxSpec(ds, stackRoot)); err != nil {
		return nil, fmt.Errorf("nginx: %w", err)
	}
	time.Sleep(2 * time.Second) // let nginx bind :80 before the first challenge

	for _, d := range ds.Domains {
		if hasCert(stackRoot, d.Host) {
			continue
		}
		if err := obtainCert(ctx, dx, ds, stackRoot, d.Host); err != nil {
			return nil, err
		}
	}

	// Re-render after cert work so newly-issued HTTPS blocks appear, and reload nginx whenever the
	// rendered conf changed — from a fresh cert OR a domains/upstream edit pushed from cloud. The conf
	// is a bind-mounted file (not part of the nginx container spec hash), so a config change never
	// recreates the container; reloading only on new-cert left plain edits inert (file updated on disk,
	// running nginx kept the stale conf). Reload on ANY change so cloud-side edits take effect next tick.
	rerendered, err := writeNginxConf(stackRoot, ds.Domains)
	if err != nil {
		return nil, err
	}
	if changed || rerendered {
		if code, out, err := dx.Exec(ctx, SvcNginx, []string{"nginx", "-s", "reload"}); err != nil || code != 0 {
			return nil, fmt.Errorf("nginx reload (%d): %v %s", code, err, tailOut(out))
		}
	}

	return readCerts(stackRoot, ds.Domains), nil
}

// RenewCerts renews any near-expiry certs (idempotent; certbot no-ops when nothing is due) and
// reloads nginx. Driven by the agent's renewal ticker.
func RenewCerts(ctx context.Context, dx *dockerx.Client, stackRoot string) error {
	spec := certbotSpec(stackRoot, "certbot-renew", []string{
		"renew", "--webroot", "-w", "/var/www/letsencrypt",
		"--config-dir", "/etc/letsencrypt", "--work-dir", "/var/lib/letsencrypt", "--logs-dir", "/var/log/letsencrypt", "-n",
	})
	code, out, err := dx.RunToCompletion(ctx, spec)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("certbot renew exited %d: %s", code, tailOut(out))
	}
	_, _, _ = dx.Exec(ctx, SvcNginx, []string{"nginx", "-s", "reload"})
	return nil
}

// writeNginxConf writes the rendered config to conf.d/vritti.conf, reporting whether the file
// content actually changed so the caller can reload nginx only when needed.
func writeNginxConf(stackRoot string, domains []cloudapi.DomainRoute) (bool, error) {
	path := filepath.Join(stackRoot, "nginx", "conf.d", "vritti.conf")
	next := []byte(RenderNginxConf(stackRoot, domains))
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, next) {
		return false, nil
	}
	if err := os.WriteFile(path, next, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// obtainCert runs certbot (webroot HTTP-01) for one host.
func obtainCert(ctx context.Context, dx *dockerx.Client, ds cloudapi.DesiredState, stackRoot, host string) error {
	args := []string{
		"certonly", "--webroot", "-w", "/var/www/letsencrypt",
		"--email", ds.AcmeEmail, "--agree-tos", "--no-eff-email", "-n",
		"--config-dir", "/etc/letsencrypt", "--work-dir", "/var/lib/letsencrypt", "--logs-dir", "/var/log/letsencrypt",
		"-d", host,
	}
	if ds.AcmeStaging {
		args = append(args, "--staging")
	}
	name := "certbot-" + strings.ReplaceAll(host, ".", "-")
	spec := certbotSpec(stackRoot, name, args)
	if err := dx.PullImage(ctx, spec.Image); err != nil {
		return err
	}
	code, out, err := dx.RunToCompletion(ctx, spec)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("certbot %s exited %d: %s", host, code, tailOut(out))
	}
	return nil
}

// certbotSpec is a one-shot certbot container sharing the cert dir + ACME webroot with nginx.
func certbotSpec(stackRoot, name string, args []string) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:    name,
		Service: "certbot",
		Image:   certbotImage,
		Cmd:     args,
		Binds: []string{
			filepath.Join(stackRoot, leDir) + ":/etc/letsencrypt",
			filepath.Join(stackRoot, leDir, "www") + ":/var/www/letsencrypt",
		},
		Network: Network,
	}
}

// readCerts reads each domain's live fullchain and reports its validity window.
func readCerts(stackRoot string, domains []cloudapi.DomainRoute) []cloudapi.CertReport {
	reports := make([]cloudapi.CertReport, 0, len(domains))
	for _, d := range domains {
		cert, err := parseCert(filepath.Join(certLive(stackRoot, d.Host), "fullchain.pem"))
		if err != nil {
			continue
		}
		reports = append(reports, cloudapi.CertReport{
			Host:     d.Host,
			NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
			IssuedAt: cert.NotBefore.UTC().Format(time.RFC3339),
		})
	}
	return reports
}

// parseCert decodes the leaf certificate from a PEM fullchain.
func parseCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// tailOut trims command output to a readable tail for error messages.
func tailOut(s string) string {
	if len(s) > 1500 {
		return "…" + s[len(s)-1500:]
	}
	return s
}
