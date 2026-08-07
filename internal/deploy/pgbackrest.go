package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// StanzaName is the pgBackRest stanza for the core database.
const StanzaName = "core"

// PostgresPGDataDir is the in-container PGDATA path (matches pg1-path in the config and PGDATA in PostgresSpec).
const PostgresPGDataDir = "/var/lib/postgresql/data/pgdata"

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

// pgbrStanzaInfo is the subset of `pgbackrest info --output=json` we parse (one element per stanza).
type pgbrStanzaInfo struct {
	Name   string `json:"name"`
	Backup []struct {
		Label     string `json:"label"`
		Type      string `json:"type"`
		Timestamp struct {
			Start int64 `json:"start"`
			Stop  int64 `json:"stop"`
		} `json:"timestamp"`
		Info struct {
			Size       uint64 `json:"size"`
			Repository struct {
				Delta uint64 `json:"delta"`
			} `json:"repository"`
		} `json:"info"`
		// Archive.Start is the first WAL segment of the backup; its leading 8 hex chars are the timeline id.
		Archive struct {
			Start string `json:"start"`
		} `json:"archive"`
		// Annotation carries our own tags (trigger=scheduled|manual|initial); absent on older pgBackRest.
		Annotation map[string]string `json:"annotation"`
	} `json:"backup"`
}

// parseTimeline extracts the timeline id from a WAL segment name (its leading 8 hex chars). 0 if unparseable.
func parseTimeline(walStart string) int {
	if len(walStart) < 8 {
		return 0
	}
	tl, err := strconv.ParseInt(walStart[:8], 16, 32)
	if err != nil {
		return 0
	}
	return int(tl)
}

// CollectBackupInfo runs `pgbackrest info --output=json` inside the running Postgres container and parses the
// core stanza's backup inventory for the admin UI's timeline + recovery window. Use CollectBackupInfoOffline
// when the deployment is stopped (Postgres removed).
func CollectBackupInfo(ctx context.Context, dx *dockerx.Client) (*cloudapi.BackupInfo, error) {
	code, out, err := dx.Exec(ctx, SvcPostgres, pgbackrestExec("info --output=json"))
	if err != nil {
		return nil, fmt.Errorf("pgbackrest info exec: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("pgbackrest info failed (exit %d): %s", code, out)
	}
	return parseBackupInfo(out)
}

// CollectBackupInfoOffline reads the same inventory WITHOUT a running Postgres — it runs `pgbackrest info` in a
// one-off container that mounts the repo + config read-only. `info` reads the repository (not the live cluster),
// so the backup list stays visible while the deployment is stopped.
func CollectBackupInfoOffline(ctx context.Context, dx *dockerx.Client, image, stackRoot string) (*cloudapi.BackupInfo, error) {
	code, out, err := dx.RunToCompletion(ctx, InfoSpec(image, stackRoot))
	if err != nil {
		return nil, fmt.Errorf("pgbackrest info (offline) run: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("pgbackrest info (offline) failed (exit %d): %s", code, out)
	}
	return parseBackupInfo(out)
}

// InfoSpec is the one-off container that reads the pgBackRest inventory offline (repo + config, read-only).
func InfoSpec(image, stackRoot string) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:    SvcPostgresInfo,
		Service: SvcPostgresInfo,
		Image:   image,
		Cmd:     []string{"su", "postgres", "-c", "pgbackrest --stanza=" + StanzaName + " info --output=json"},
		Binds: []string{
			filepath.Join(stackRoot, "pgbackrest") + ":/etc/pgbackrest:ro",
			filepath.Join(stackRoot, "backup") + ":/var/lib/pgbackrest:ro",
		},
		Network: Network,
	}
}

// parseBackupInfo turns `pgbackrest info --output=json` output into the core stanza's backup inventory.
func parseBackupInfo(out string) (*cloudapi.BackupInfo, error) {
	// pgBackRest may emit a warning line before the JSON payload — start at the first '['.
	start := strings.IndexByte(out, '[')
	if start < 0 {
		return nil, fmt.Errorf("pgbackrest info: no JSON array in output: %s", out)
	}
	var stanzas []pgbrStanzaInfo
	if err := json.Unmarshal([]byte(out[start:]), &stanzas); err != nil {
		return nil, fmt.Errorf("pgbackrest info parse: %w", err)
	}
	info := &cloudapi.BackupInfo{}
	for _, st := range stanzas {
		if st.Name != StanzaName {
			continue
		}
		for _, b := range st.Backup {
			trigger := b.Annotation["trigger"]
			if trigger == "" {
				trigger = BackupTriggerScheduled // older pgBackRest (no annotations) or an un-tagged backup
			}
			info.Backups = append(info.Backups, cloudapi.BackupEntry{
				Label:     b.Label,
				Type:      b.Type,
				StartUnix: b.Timestamp.Start,
				StopUnix:  b.Timestamp.Stop,
				SizeBytes: b.Info.Size,
				RepoBytes: b.Info.Repository.Delta,
				Timeline:  parseTimeline(b.Archive.Start),
				Trigger:   trigger,
			})
		}
	}
	return info, nil
}

// SvcPostgresRestore is the one-off container that runs the offline pgBackRest restore into PGDATA.
const SvcPostgresRestore = "core-db-restore"

// SvcPostgresInfo is the one-off container that reads the pgBackRest inventory when Postgres isn't running.
const SvcPostgresInfo = "core-db-info"

// pgRestoreTargetTime converts an RFC3339 instant into the timestamp format pgBackRest/Postgres recovery
// expects ("2006-01-02 15:04:05-07:00"). A value that doesn't parse is passed through unchanged.
func pgRestoreTargetTime(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return rfc3339
	}
	return t.Format("2006-01-02 15:04:05-07:00")
}

// pgRestoreCommand builds the `su postgres -c "pgbackrest ... restore"` argv for the restore container. A
// --delta restore only overwrites files that differ, so it is fast on an existing cluster. The target:
//   - targetTime -> --type=time --target="<ts>" --target-action=promote (point-in-time)
//   - setLabel   -> --set=<label> --type=immediate --target-action=promote (that backup's consistency point)
//   - neither     -> latest backup, recover to the end of the WAL archive
func pgRestoreCommand(targetTime, setLabel string) []string {
	// The live Postgres container is force-removed before the restore, which leaves a stale postmaster.pid in
	// PGDATA — pgBackRest refuses ("unable to restore while PostgreSQL is running", exit 38) unless it's gone.
	// Safe to delete here: no Postgres process is running (its container was removed), exactly the case the
	// pgBackRest hint says to remove it in.
	args := "rm -f " + PostgresPGDataDir + "/postmaster.pid && pgbackrest --stanza=" + StanzaName + " --delta"
	switch {
	case targetTime != "":
		args += fmt.Sprintf(` --type=time "--target=%s" --target-action=promote`, pgRestoreTargetTime(targetTime))
	case setLabel != "":
		args += " --set=" + setLabel + " --type=immediate --target-action=promote"
	}
	args += " restore"
	return []string{"su", "postgres", "-c", args}
}

// RestoreSpec is the one-off container that performs the offline restore: same Postgres image (it ships
// pgBackRest), mounting PGDATA + the encrypted repo + the config read-only, running the restore as the
// postgres user. The live Postgres container MUST be stopped first — the caller orchestrates that.
func RestoreSpec(image, stackRoot, targetTime, setLabel string) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:    SvcPostgresRestore,
		Service: SvcPostgresRestore,
		Image:   image,
		Cmd:     pgRestoreCommand(targetTime, setLabel),
		Binds: []string{
			PostgresDataDir(stackRoot) + ":/var/lib/postgresql/data",
			filepath.Join(stackRoot, "pgbackrest") + ":/etc/pgbackrest:ro",
			filepath.Join(stackRoot, "backup") + ":/var/lib/pgbackrest",
		},
		Network: Network,
	}
}

// Backup trigger tags (stored as a pgBackRest annotation so the UI can tell auto from manual backups apart).
const (
	BackupTriggerScheduled = "scheduled" // hourly incr / daily full ticker
	BackupTriggerManual    = "manual"    // operator pressed "Backup now"
	BackupTriggerInitial   = "initial"   // first full taken when backups were enabled
)

// SupportsBackupAnnotations reports whether the Postgres image's pgBackRest is new enough (>= 2.41) to accept
// `--annotation`. Passing that flag to an older binary would FAIL the backup, so the agent probes once and
// only tags when supported; an older binary just leaves every backup tagged "scheduled".
func SupportsBackupAnnotations(ctx context.Context, dx *dockerx.Client) bool {
	code, out, err := dx.Exec(ctx, SvcPostgres, []string{"pgbackrest", "version"})
	if err != nil || code != 0 {
		return false
	}
	fields := strings.Fields(out) // e.g. "pgBackRest 2.50"
	if len(fields) < 2 {
		return false
	}
	var major, minor int
	if _, err := fmt.Sscanf(fields[len(fields)-1], "%d.%d", &major, &minor); err != nil {
		return false
	}
	return major > 2 || (major == 2 && minor >= 41)
}

// RunBackup runs a pgBackRest backup of the given type ("full"|"diff"|"incr") inside Postgres, tagging it with
// its trigger (scheduled|manual|initial) via an annotation when the binary supports it (see SupportsBackupAnnotations).
func RunBackup(ctx context.Context, dx *dockerx.Client, backupType, trigger string, annotate bool) error {
	args := "--type=" + backupType
	if annotate && trigger != "" {
		args += " --annotation=trigger=" + trigger
	}
	args += " backup"
	code, out, err := dx.Exec(ctx, SvcPostgres, pgbackrestExec(args))
	if err != nil {
		return fmt.Errorf("%s backup exec: %w", backupType, err)
	}
	if code != 0 {
		return fmt.Errorf("%s backup failed (exit %d): %s", backupType, code, out)
	}
	return nil
}
