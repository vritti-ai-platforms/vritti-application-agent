package deploy

import (
	"context"
	"fmt"
	"strings"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// StanzaName is the pgBackRest stanza for the core database.
const StanzaName = "core"

// Backup secret keys sourced from the `/backup` secret-store folder. Both cipher passphrases live in the
// secret store (NOT on the VM): a VM-local key would make the OFFSITE repo2 backups unrecoverable after a
// VM/agent loss — the exact scenario backups exist for. repo1 (local) is always on; repo2 (offsite S3) is
// gated on its cipher passphrase — setting PGBACKREST_REPO2_CIPHER_PASS is the switch that says "offsite is
// intended", which then requires the full S3 credential set so a partial config fails loudly.
const (
	BackupRepo1CipherPass = "PGBACKREST_REPO1_CIPHER_PASS"
	BackupRepo2CipherPass = "PGBACKREST_REPO2_CIPHER_PASS"
)

// backupS3Keys are the offsite (repo2) object-store credentials, required once the repo2 cipher passphrase
// is set.
var backupS3Keys = []string{"S3_ENDPOINT", "S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"}

// Backup mode strings reported to cloud so the admin UI can show whether offsite is configured.
const (
	BackupStateOff     = "off"           // backups add-on disabled
	BackupStateLocal   = "local"         // repo1 only (encrypted, on the VM disk)
	BackupStateOffsite = "local+offsite" // repo1 + encrypted repo2 on an S3-compatible store
)

// ValidateBackupSecrets checks the `/backup` folder has everything pgBackRest needs BEFORE the stanza is
// created, so a missing key surfaces as a clear reconcile error instead of standing up an unencrypted or
// half-configured repo. repo1's cipher is always required; offsite (repo2) is gated on its cipher passphrase
// — once PGBACKREST_REPO2_CIPHER_PASS is set, all four S3 credentials must also be present.
func ValidateBackupSecrets(env map[string]string) error {
	var missing []string
	if strings.TrimSpace(env[BackupRepo1CipherPass]) == "" {
		missing = append(missing, BackupRepo1CipherPass)
	}
	if strings.TrimSpace(env[BackupRepo2CipherPass]) != "" {
		for _, k := range backupS3Keys {
			if strings.TrimSpace(env[k]) == "" {
				missing = append(missing, k)
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required /backup secrets: %s", strings.Join(missing, ", "))
	}
	return nil
}

// BackupState reports the configured backup topology so cloud/UI can show it. Assumes ValidateBackupSecrets
// passed: repo1 is always present, and offsite repo2 is on exactly when its cipher passphrase (+ S3 creds)
// is set. Returns BackupStateLocal or BackupStateOffsite.
func BackupState(env map[string]string) string {
	if strings.TrimSpace(env[BackupRepo2CipherPass]) != "" {
		return BackupStateOffsite
	}
	return BackupStateLocal
}

// pgbackrest commands run as the postgres OS user inside the Postgres container (it owns PGDATA
// and connects over the trusted local socket). archive_command uses the same binary + config.
func pgbackrestExec(args string) []string {
	return []string{"su", "postgres", "-c", "pgbackrest --stanza=" + StanzaName + " " + args}
}

// RenderPgBackRestConf builds /etc/pgbackrest/pgbackrest.conf: an always-on encrypted local repo1, and —
// when the S3_* keys are present in `backup` (the dedicated `/backup` secret-store folder, NOT core-server's
// media bucket) — an encrypted repo2 on any S3-compatible store. Both cipher passphrases come from `/backup`
// (durable in the secret store, so backups survive a VM/agent loss). pgUser is the DB superuser pgBackRest
// uses. Call ValidateBackupSecrets(backup) first — this assumes the required keys are present.
func RenderPgBackRestConf(ds cloudapi.DesiredState, backup map[string]string, pgUser string) string {
	// Retention (full backups kept) comes from cloud in the database component; guard the unset/legacy 0.
	retention := 4
	if db := ds.Components.Database; db != nil && db.Backup != nil && db.Backup.Retention >= 1 {
		retention = db.Backup.Retention
	}

	var b strings.Builder
	b.WriteString("[global]\n")
	b.WriteString("repo1-path=/var/lib/pgbackrest\n")
	fmt.Fprintf(&b, "repo1-retention-full=%d\n", retention)
	b.WriteString("repo1-cipher-type=aes-256-cbc\n")
	fmt.Fprintf(&b, "repo1-cipher-pass=%s\n", backup[BackupRepo1CipherPass])

	// repo2 = any S3-compatible object store (Cloudflare R2, AWS S3, MinIO, …), gated on the repo2 cipher
	// passphrase (the offsite switch) plus the full S3 credential set — matching ValidateBackupSecrets so we
	// never write a half-configured or unencrypted repo2. Region defaults to "auto" (R2/MinIO); AWS needs a
	// real region via S3_REGION.
	endpoint, bucket := backup["S3_ENDPOINT"], backup["S3_BUCKET"]
	key, secret := backup["S3_ACCESS_KEY_ID"], backup["S3_SECRET_ACCESS_KEY"]
	if backup[BackupRepo2CipherPass] != "" && endpoint != "" && bucket != "" && key != "" && secret != "" {
		region := backup["S3_REGION"]
		if region == "" {
			region = "auto"
		}
		b.WriteString("repo2-type=s3\n")
		fmt.Fprintf(&b, "repo2-s3-endpoint=%s\n", endpoint)
		fmt.Fprintf(&b, "repo2-s3-bucket=%s\n", bucket)
		fmt.Fprintf(&b, "repo2-s3-region=%s\n", region)
		b.WriteString("repo2-s3-uri-style=path\n")
		fmt.Fprintf(&b, "repo2-s3-key=%s\n", key)
		fmt.Fprintf(&b, "repo2-s3-key-secret=%s\n", secret)
		fmt.Fprintf(&b, "repo2-path=/pgbackrest/%s\n", ds.DeploymentID)
		fmt.Fprintf(&b, "repo2-retention-full=%d\n", retention)
		b.WriteString("repo2-cipher-type=aes-256-cbc\n")
		fmt.Fprintf(&b, "repo2-cipher-pass=%s\n", backup[BackupRepo2CipherPass])
	}

	b.WriteString("compress-type=lz4\n")
	b.WriteString("log-level-console=info\n")
	b.WriteString("start-fast=y\n\n")

	fmt.Fprintf(&b, "[%s]\n", StanzaName)
	b.WriteString("pg1-path=/var/lib/postgresql/data/pgdata\n")
	b.WriteString("pg1-port=5432\n")
	// The DB superuser is POSTGRES_USER (the deployment owner), NOT "postgres" — that role doesn't
	// exist, so pgBackRest can't reach the cluster if it connects as postgres. Local socket = trust.
	fmt.Fprintf(&b, "pg1-user=%s\n", pgUser)
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
