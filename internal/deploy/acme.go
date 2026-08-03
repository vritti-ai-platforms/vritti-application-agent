package deploy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/acmedns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

const (
	letsEncryptProd    = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	acmeDNSImage   = "joohoi/acme-dns:v1.0"
	acmeDNSAPIPort = 8080
	// renewWindow — reissue once the wildcard is within this of expiry (LE certs live 90d).
	renewWindow = 30 * 24 * time.Hour
)

// acmeDNSZone is the delegated challenge zone the bundled acme-dns is authoritative for.
func acmeDNSZone(baseDomain string) string { return "acme." + baseDomain }

// acmeDNSNameserver is the hostname the challenge zone is delegated to. It is a SIBLING of the zone
// (under <base>, NOT under acme.<base>), so the parent DNS (Cloudflare et al.) resolves its A record
// normally — no in-zone glue, which is exactly the setup a self-referential nsname breaks on.
func acmeDNSNameserver(baseDomain string) string { return "ns." + baseDomain }

// AcmeDNSAPIBase is the in-network URL lego uses to reach the bundled acme-dns HTTP API (the agent
// must share the stack network so this name resolves).
func AcmeDNSAPIBase() string { return fmt.Sprintf("http://%s:%d", SvcAcmeDns, acmeDNSAPIPort) }

// waitForAcmeDNS blocks until the bundled acme-dns HTTP API accepts TCP connections, or ~20s passes.
// When the wildcard is issued BEFORE the stack (cert-first), acme-dns was only just applied, so lego's
// first register/record call would otherwise race the container's boot and error.
func waitForAcmeDNS(ctx context.Context) {
	addr := net.JoinHostPort(SvcAcmeDns, strconv.Itoa(acmeDNSAPIPort))
	for range 40 {
		if conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// AcmeDnsSpec is the bundled acme-dns: public authoritative DNS on :53 (Let's Encrypt resolves the
// wildcard challenge TXTs here) + an HTTP API on the private network (lego writes the rotating TXTs).
func AcmeDnsSpec(stackRoot string) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:    SvcAcmeDns,
		Service: SvcAcmeDns,
		Image:   acmeDNSImage,
		Binds: []string{
			filepath.Join(stackRoot, "acme-dns", "config") + ":/etc/acme-dns:ro",
			filepath.Join(stackRoot, "acme-dns", "data") + ":/var/lib/acme-dns",
		},
		Ports:        map[string]string{"53/udp": "53", "53/tcp": "53"}, // published for LE resolvers
		ExposedPorts: []string{fmt.Sprintf("%d/tcp", acmeDNSAPIPort)},
		Network:      Network,
		Restart:      true,
		MemLimit:     64 * mib,
	}
}

// WriteAcmeDnsConfig renders acme-dns's config for this deployment — authoritative for acme.<base>,
// delegated via a SIBLING nameserver ns.<base> (not self-referential), so the parent DNS can resolve
// the nameserver without in-zone glue. Serves the nameserver's A and the zone's NS record.
func WriteAcmeDnsConfig(stackRoot, baseDomain, publicIP string) error {
	zone := acmeDNSZone(baseDomain)
	ns := acmeDNSNameserver(baseDomain)
	cfg := fmt.Sprintf(`[general]
listen = "0.0.0.0:53"
protocol = "both"
domain = "%s"
nsname = "%s"
nsadmin = "admin.%s"
records = ["%s. A %s", "%s. NS %s."]
debug = false

[database]
engine = "sqlite3"
connection = "/var/lib/acme-dns/acme-dns.db"

[api]
ip = "0.0.0.0"
port = "%d"
disable_registration = false
tls = "none"

[logconfig]
loglevel = "info"
logtype = "stdout"
logformat = "json"
`, zone, ns, baseDomain, ns, publicIP, zone, ns, acmeDNSAPIPort)

	cfgDir := filepath.Join(stackRoot, "acme-dns", "config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(stackRoot, "acme-dns", "data"), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cfgDir, "config.cfg"), []byte(cfg), 0o644)
}

// PublicIP best-effort discovers the VM's public IPv4 (needed in the acme-dns self-records so the
// operator can delegate acme.<base> to this host).
func PublicIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// certNeedsIssue reports whether the wildcard needs (re)issuing — missing or within the renew window.
func certNeedsIssue(stackRoot, baseDomain string) bool {
	cert, err := parseCert(filepath.Join(certLive(stackRoot, baseDomain), "fullchain.pem"))
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) < renewWindow
}

// acmeUser implements lego's registration.User — the ACME account (email + account key + registration).
type acmeUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// IssueWildcard obtains (or renews) the single `*.<base>` + `<base>` cert via DNS-01 through the
// LOCAL acme-dns, with lego embedded in-process — no certbot, no per-host certs. One wildcard covers
// api./git./every tenant subdomain. Returns:
//   - (delegation, false, nil) → a one-time CNAME the operator must add before issuance can complete
//   - (nil, true, nil)         → issued; written to live/<base>/{fullchain,privkey}.pem for nginx
func IssueWildcard(baseDomain, email, acmeDNSAPIBase, stackRoot, publicIP string, staging bool) (*cloudapi.AcmeChallengeDelegation, bool, error) {
	if baseDomain == "" {
		return nil, false, nil
	}

	// acme-dns account storage — a persisted JSON file, so the account registers once and renewals
	// reuse it (the provider builds file-backed storage from StoragePath).
	provider, err := acmedns.NewDNSProviderConfig(&acmedns.Config{
		APIBase:     acmeDNSAPIBase,
		StoragePath: filepath.Join(stackRoot, leDir, "acmedns.json"),
	})
	if err != nil {
		return nil, false, fmt.Errorf("acme-dns provider: %w", err)
	}

	// ACME account key — persisted, so the same account is used across renewals.
	accKey, err := loadOrCreateAccountKey(filepath.Join(stackRoot, leDir, "account.key"))
	if err != nil {
		return nil, false, err
	}
	user := &acmeUser{email: email, key: accKey}

	cfg := lego.NewConfig(user)
	cfg.CADirURL = letsEncryptProd
	if staging {
		cfg.CADirURL = letsEncryptStaging
	}
	cfg.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, false, fmt.Errorf("lego client: %w", err)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, false, fmt.Errorf("set dns01 provider: %w", err)
	}

	// Register the ACME account (a fresh account key registers once; harmless thereafter).
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, false, fmt.Errorf("acme register: %w", err)
	}
	user.reg = reg

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{"*." + baseDomain, baseDomain},
		Bundle:  true,
	})
	if err != nil {
		// First issuance for this base: acme-dns just registered an account and needs the one-time
		// CNAME wired before Let's Encrypt can resolve the challenge. Surface it instead of failing.
		var need acmedns.ErrCNAMERequired
		if errors.As(err, &need) {
			return &cloudapi.AcmeChallengeDelegation{
				Name:       need.FQDN,
				Target:     need.Target,
				Zone:       acmeDNSZone(baseDomain),
				Nameserver: acmeDNSNameserver(baseDomain),
				ServerIP:   publicIP,
			}, false, nil
		}
		return nil, false, fmt.Errorf("obtain wildcard: %w", err)
	}

	if err := writeCert(stackRoot, baseDomain, res.Certificate, res.PrivateKey); err != nil {
		return nil, false, err
	}
	return nil, true, nil
}

// writeCert persists the fullchain + key where nginx (and hasCert) expect them: live/<base>/.
func writeCert(stackRoot, baseDomain string, fullchain, privkey []byte) error {
	dir := certLive(stackRoot, baseDomain)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), fullchain, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "privkey.pem"), privkey, 0o600)
}

// loadOrCreateAccountKey returns a persisted EC P-256 ACME account key, creating it on first use.
func loadOrCreateAccountKey(path string) (crypto.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("account key: no PEM in %s", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}
