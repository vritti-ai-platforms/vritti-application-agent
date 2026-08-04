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

// leDir is the on-host Let's Encrypt dir: the wildcard cert under live/<base>/, plus the acme-dns
// account (acmedns.json) and the ACME account key. Shared read-only into nginx.
const leDir = "letsencrypt"

// EdgeDirs are the host dirs the managed edge needs before nginx runs.
func EdgeDirs(stackRoot string) []string {
	return []string{
		filepath.Join(stackRoot, "nginx", "conf.d"),
		filepath.Join(stackRoot, "logs", "nginx"),
		filepath.Join(stackRoot, leDir),
		webRoot(stackRoot),
	}
}

// certLive is the host path to the wildcard cert's live directory (keyed by the base domain).
func certLive(stackRoot, host string) string {
	return filepath.Join(stackRoot, leDir, "live", host)
}

// hasCert reports whether a live fullchain already exists for host.
func hasCert(stackRoot, host string) bool {
	_, err := os.Stat(filepath.Join(certLive(stackRoot, host), "fullchain.pem"))
	return err == nil
}

// DerivedRoutes computes the proxy routes from the base domain — routing is DERIVED, not
// operator-configured. api.<base> → core-server on its real PORT; git.<base> → gitea when the add-on
// is on. The tenant/core-web wildcard (*.<base>) is served statically, handled in RenderNginxConf.
func DerivedRoutes(baseDomain string, corePort int, gitea bool) []cloudapi.DomainRoute {
	if baseDomain == "" {
		return nil
	}
	routes := []cloudapi.DomainRoute{
		{Host: "api." + baseDomain, Upstream: fmt.Sprintf("%s:%d", SvcCore, corePort)},
	}
	if gitea {
		routes = append(routes, cloudapi.DomainRoute{Host: "git." + baseDomain, Upstream: SvcGitea + ":3000"})
	}
	return routes
}

// RenderNginxConf builds the edge config off the single *.<base> wildcard cert: an HTTP→HTTPS
// redirect, a proxy block per derived route (api./git.), and the wildcard static block serving
// core-web/MF bundles for every other (tenant) subdomain. Cert-aware: before the wildcard is issued
// it emits HTTP-only (nginx stays valid); the HTTPS blocks appear once the cert exists. corePort is
// the port core-server binds — the *.<base> block proxies same-origin /api/* there (tenant core-web
// calls /api/... on its own subdomain).
func RenderNginxConf(stackRoot, baseDomain string, corePort int, routes []cloudapi.DomainRoute) string {
	var b strings.Builder
	b.WriteString("server {\n  listen 80;\n  server_name _;\n  location / { return 301 https://$host$request_uri; }\n}\n\n")

	if baseDomain == "" || !hasCert(stackRoot, baseDomain) {
		return b.String() // wildcard not issued yet → HTTP only
	}
	cert := "/etc/letsencrypt/live/" + baseDomain
	tls := "  ssl_certificate " + cert + "/fullchain.pem;\n  ssl_certificate_key " + cert + "/privkey.pem;\n" +
		"  ssl_protocols TLSv1.2 TLSv1.3;\n  client_max_body_size 25m;\n"

	// Specific proxy hosts (api./git.) — nginx matches these before the *.<base> catch-all.
	for _, r := range routes {
		b.WriteString("server {\n  listen 443 ssl;\n  http2 on;\n  server_name " + r.Host + ";\n" + tls)
		b.WriteString("  location / {\n    proxy_pass http://" + r.Upstream + ";\n    proxy_http_version 1.1;\n")
		b.WriteString("    proxy_set_header Host $host;\n    proxy_set_header X-Real-IP $remote_addr;\n")
		b.WriteString("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $scheme;\n")
		b.WriteString("    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection \"upgrade\";\n  }\n}\n\n")
	}

	// Wildcard catch-all: tenant subdomains serve the static core-web SPA, and its same-origin /api/*
	// calls proxy (prefix stripped) to core-server — mirroring the cloud edge — so /api/auth/status hits
	// the API instead of returning index.html. The /api/ location must precede the SPA try_files.
	coreUpstream := fmt.Sprintf("http://%s:%d", SvcCore, corePort)
	b.WriteString("server {\n  listen 443 ssl;\n  http2 on;\n  server_name *." + baseDomain + ";\n" + tls)
	b.WriteString("  location /api/ {\n    rewrite ^/api/(.*)$ /$1 break;\n    proxy_pass " + coreUpstream + ";\n    proxy_http_version 1.1;\n")
	b.WriteString("    proxy_set_header Host $host;\n    proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $scheme;\n")
	b.WriteString("    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection \"upgrade\";\n")
	b.WriteString("    proxy_buffering off;\n    proxy_read_timeout 3600s;\n  }\n")
	b.WriteString("  root /var/www/core-web;\n  location / { try_files $uri /index.html; }\n}\n\n")
	return b.String()
}

// EnsureWildcard brings up the bundled acme-dns and issues/renews the single *.<base> wildcard via
// lego (DNS-01). It needs no app config, so the agent runs it BEFORE provisioning the stack and gates
// provisioning on the result — the cert is created first, then the containers start.
//
// It is pre-flight-guarded: once the acme-dns account exists (the CNAME target is known), it will NOT
// call Let's Encrypt until dnsDelegationReady confirms the operator's records actually resolve, which
// stops the repeated propagation-timeout bursts (and LE churn) during DNS propagation. On the very
// first attempt (no account yet) it calls lego once to register the account + surface the one-time
// CNAME. The (categorized) result tells the agent which condition/event/cadence to use — no hard error
// for a DNS/throttle wait; the agent enforces the rate-limit/failure backoff by not reconciling inside
// its backoff window. `err` carries the underlying detail (nil, or set for Error/RateLimited/propagation).
func EnsureWildcard(ctx context.Context, dx *dockerx.Client, ds cloudapi.DesiredState, stackRoot string, prev *cloudapi.AcmeChallengeDelegation) (WildcardResult, error) {
	for _, dir := range EdgeDirs(stackRoot) {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return WildcardResult{Outcome: WildcardOutcomeError}, err
		}
	}

	// Bundled acme-dns — authoritative for acme.<base>, so lego can prove control for the wildcard. The
	// VM's public IP goes in acme-dns' self-records AND the reported zone-delegation glue (A record); a
	// managed edge can't work without it, so a lookup failure is fatal rather than a broken delegation.
	publicIP, err := PublicIP(ctx)
	if err != nil || publicIP == "" {
		return WildcardResult{Outcome: WildcardOutcomeError}, fmt.Errorf("resolve public IP (required for the managed edge acme-dns): %w", err)
	}
	if err := WriteAcmeDnsConfig(stackRoot, ds.BaseDomain, publicIP); err != nil {
		return WildcardResult{Outcome: WildcardOutcomeError}, err
	}
	if err := Apply(ctx, dx, AcmeDnsSpec(stackRoot)); err != nil {
		return WildcardResult{Outcome: WildcardOutcomeError}, fmt.Errorf("acme-dns: %w", err)
	}
	// lego registers/updates records over acme-dns' HTTP API — wait for it to accept connections
	// (it's applied here, not standing for a while as when the stack ran first), else the first
	// registration races the container's boot and errors.
	waitForAcmeDNS(ctx)

	base := ds.BaseDomain
	certs := readCerts(stackRoot, []cloudapi.DomainRoute{{Host: base}})

	// Already have a valid, non-expiring wildcard — nothing to do.
	if !certNeedsIssue(stackRoot, base) {
		return WildcardResult{Outcome: WildcardOutcomeIssued, Certs: certs}, nil
	}

	// Recover the known CNAME target (from a prior in-memory delegation or acme-dns' persisted storage),
	// so we can pre-flight the delegation and keep surfacing the records across restarts.
	target := ""
	if prev != nil {
		target = prev.Target
	}
	if target == "" {
		if t, ok := acmeDNSTarget(stackRoot); ok {
			target = t
		}
	}
	haveAccount := target != ""

	del := prev
	if del == nil && haveAccount {
		del = delegationFor(base, target, publicIP)
	}

	// Once the acme-dns account exists, gate the LE call on the delegation actually being live.
	if haveAccount {
		if ready, reason := dnsDelegationReady(ctx, base, publicIP, target); !ready {
			return WildcardResult{Delegation: del, Outcome: WildcardOutcomeAwaitingDNS, Certs: certs},
				fmt.Errorf("dns delegation not ready: %s", reason)
		}
	}

	// The only place we hit Let's Encrypt: either the first attempt (registers the account + surfaces
	// the one-time CNAME) or a pre-flight-confirmed retry.
	acmeEmail := ""
	if ds.Components.Edge != nil {
		acmeEmail = ds.Components.Edge.AcmeEmail
	}
	newDel, issued, err := IssueWildcard(base, acmeEmail, AcmeDNSAPIBase(), stackRoot, publicIP, ds.AcmeStaging)
	if err != nil {
		switch {
		case IsRateLimitError(err):
			return WildcardResult{Delegation: del, Outcome: WildcardOutcomeRateLimited, Certs: certs}, err
		case IsDNSPropagationError(err):
			if del == nil {
				if t, ok := acmeDNSTarget(stackRoot); ok {
					del = delegationFor(base, t, publicIP)
				}
			}
			return WildcardResult{Delegation: del, Outcome: WildcardOutcomeAwaitingDNS, Certs: certs}, err
		default:
			return WildcardResult{Delegation: del, Outcome: WildcardOutcomeError, Certs: certs}, err
		}
	}
	if newDel != nil {
		// First run: the account just registered; the one-time CNAME must be added before LE can validate.
		return WildcardResult{Delegation: newDel, Outcome: WildcardOutcomeAwaitingDNS, Certs: certs}, nil
	}
	if issued {
		return WildcardResult{Outcome: WildcardOutcomeIssued, Certs: readCerts(stackRoot, []cloudapi.DomainRoute{{Host: base}})}, nil
	}
	// Defensive: no cert and no delegation — treat as still awaiting so we re-check rather than error.
	return WildcardResult{Delegation: del, Outcome: WildcardOutcomeAwaitingDNS, Certs: certs}, nil
}

// EnsureNginx renders the edge config off the issued wildcard (routing derived from the base domain),
// syncs the static web bundles, and (re)starts nginx. Run AFTER the stack is provisioned so upstreams
// resolve and AFTER the wildcard exists (gated by the caller), so nginx comes up serving HTTPS.
func EnsureNginx(ctx context.Context, dx *dockerx.Client, ds cloudapi.DesiredState, stackRoot string, coreEnv []string) ([]cloudapi.CertReport, error) {
	giteaEnabled := ds.Components.Gitea != nil && ds.Components.Gitea.Enabled
	corePort := envPort(coreEnv, DefaultCorePort)
	routes := DerivedRoutes(ds.BaseDomain, corePort, giteaEnabled)

	// Sync the static web bundles (core-web host + entitled MF remotes) into the wildcard web root.
	// First provision must surface a pull failure so a bad artifact ref is visible; once the host
	// bundle is in place we stay best-effort, so a transient registry blip can't flip a healthy
	// deployment to error (nginx serves the on-disk copy and the next tick retries).
	if _, err := SyncWebBundles(ctx, ds.WebBundles, stackRoot); err != nil {
		if !hostBundleReady(stackRoot) {
			return nil, fmt.Errorf("web bundles: %w", err)
		}
	}

	// Render (wildcard cert-aware) + ensure nginx, reload on any change (conf is a bind-mount, so a
	// change never recreates the container — reload applies it).
	changed, err := writeNginxConf(stackRoot, ds.BaseDomain, corePort, routes)
	if err != nil {
		return nil, err
	}
	if err := Apply(ctx, dx, NginxSpec(ds, stackRoot)); err != nil {
		return nil, fmt.Errorf("nginx: %w", err)
	}
	if changed {
		_, _, _ = dx.Exec(ctx, SvcNginx, []string{"nginx", "-s", "reload"})
	}

	return readCerts(stackRoot, []cloudapi.DomainRoute{{Host: ds.BaseDomain}}), nil
}

// writeNginxConf writes the rendered config to conf.d/vritti.conf, reporting whether the content changed.
func writeNginxConf(stackRoot, baseDomain string, corePort int, routes []cloudapi.DomainRoute) (bool, error) {
	path := filepath.Join(stackRoot, "nginx", "conf.d", "vritti.conf")
	next := []byte(RenderNginxConf(stackRoot, baseDomain, corePort, routes))
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, next) {
		return false, nil
	}
	if err := os.WriteFile(path, next, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// readCerts reads each cert's live fullchain and reports its validity window.
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
