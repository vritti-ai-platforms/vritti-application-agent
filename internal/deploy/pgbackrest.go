package deploy

import (
	"context"
	"fmt"
	"strings"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secrets"
)

// StanzaName is the pgBackRest stanza for the core database.
const StanzaName = "core"

// pgbackrest commands run as the postgres OS user inside the Postgres container (it owns PGDATA
// and connects over the trusted local socket). archive_command uses the same binary + config.
func pgbackrestExec(args string) []string {
	return []string{"su", "postgres", "-c", "pgbackrest --stanza=" + StanzaName + " " + args}
}

// RenderPgBackRestConf builds /etc/pgbackrest/pgbackrest.conf: an always-on encrypted local
// repo1, and — when R2 config is present in the resolved secrets — an encrypted S3 repo2 on R2.
// The cipher passphrase is a machine secret (never leaves the VM).
func RenderPgBackRestConf(ds cloudapi.DesiredState, m *secrets.Machine, resolved map[string]string) string {
	// Retention (full backups kept) comes from cloud in the desired-state; guard the unset/legacy 0.
	retention := ds.AddOns.BackupRetention
	if retention < 1 {
		retention = 4
	}

	var b strings.Builder
	b.WriteString("[global]\n")
	b.WriteString("repo1-path=/var/lib/pgbackrest\n")
	fmt.Fprintf(&b, "repo1-retention-full=%d\n", retention)
	b.WriteString("repo1-cipher-type=aes-256-cbc\n")
	fmt.Fprintf(&b, "repo1-cipher-pass=%s\n", m.PgBackRestCipherPass)

	// repo2 = Cloudflare R2 (S3-compatible), only if the operator supplied the R2 secret.
	endpoint, bucket := resolved["R2_ENDPOINT"], resolved["R2_BUCKET"]
	key, secret := resolved["R2_ACCESS_KEY_ID"], resolved["R2_SECRET_ACCESS_KEY"]
	if endpoint != "" && bucket != "" && key != "" && secret != "" {
		b.WriteString("repo2-type=s3\n")
		fmt.Fprintf(&b, "repo2-s3-endpoint=%s\n", endpoint)
		fmt.Fprintf(&b, "repo2-s3-bucket=%s\n", bucket)
		b.WriteString("repo2-s3-region=auto\n")
		b.WriteString("repo2-s3-uri-style=path\n")
		fmt.Fprintf(&b, "repo2-s3-key=%s\n", key)
		fmt.Fprintf(&b, "repo2-s3-key-secret=%s\n", secret)
		fmt.Fprintf(&b, "repo2-path=/pgbackrest/%s\n", ds.DeploymentID)
		fmt.Fprintf(&b, "repo2-retention-full=%d\n", retention)
		b.WriteString("repo2-cipher-type=aes-256-cbc\n")
		fmt.Fprintf(&b, "repo2-cipher-pass=%s\n", m.PgBackRestCipherPass)
	}

	b.WriteString("compress-type=lz4\n")
	b.WriteString("log-level-console=info\n")
	b.WriteString("start-fast=y\n\n")

	fmt.Fprintf(&b, "[%s]\n", StanzaName)
	b.WriteString("pg1-path=/var/lib/postgresql/data/pgdata\n")
	b.WriteString("pg1-port=5432\n")
	b.WriteString("pg1-user=postgres\n")
	return b.String()
}

// EnsureStanza initializes (idempotently) the pgBackRest stanza inside the Postgres container.
func EnsureStanza(ctx context.Context, dx *dockerx.Client) error {
	code, out, err := dx.Exec(ctx, SvcPostgres, pgbackrestExec("stanza-create"))
	if err != nil {
		return fmt.Errorf("stanza-create exec: %w", err)
	}
	// stanza-create is idempotent; an already-created stanza reports success or a benign message.
	if code != 0 && !strings.Contains(strings.ToLower(out), "already") {
		return fmt.Errorf("stanza-create failed (exit %d): %s", code, out)
	}
	return nil
}

// RunBackup runs a pgBackRest backup of the given type ("full" or "incr") inside Postgres.
func RunBackup(ctx context.Context, dx *dockerx.Client, backupType string) error {
	code, out, err := dx.Exec(ctx, SvcPostgres, pgbackrestExec("--type="+backupType+" backup"))
	if err != nil {
		return fmt.Errorf("%s backup exec: %w", backupType, err)
	}
	if code != 0 {
		return fmt.Errorf("%s backup failed (exit %d): %s", backupType, code, out)
	}
	return nil
}
