package deploy

import (
	"context"
	"fmt"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// EnsureManagedDatabase provisions the least-privilege roles + schemas the app expects inside the
// containerized Postgres, idempotently, by exec'ing psql as the owner (which is the container's
// superuser — POSTGRES_USER=vritti_core_owner, created at init).
//
//   - vritti_core_owner  → the superuser/owner; created at container init, migrations run as it
//   - vritti_core_app    → least-privilege runtime login the services use
//   - gitea              → least-privilege login that owns ONLY the `gitea` schema (no access
//     to core/commerce); Gitea connects as this role, sharing the DB without owner reach
//
// The core/commerce schemas themselves are created by the Drizzle migrate runner (as owner).
func EnsureManagedDatabase(ctx context.Context, dx *dockerx.Client, conn DBConn) error {
	sql := fmt.Sprintf(`
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='%[1]s') THEN
    CREATE ROLE %[1]s LOGIN PASSWORD '%[2]s';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='%[3]s') THEN
    CREATE ROLE %[3]s LOGIN PASSWORD '%[4]s';
  END IF;
END $$;
ALTER ROLE %[1]s WITH PASSWORD '%[2]s';
ALTER ROLE %[3]s WITH PASSWORD '%[4]s';
CREATE SCHEMA IF NOT EXISTS gitea AUTHORIZATION %[3]s;
ALTER SCHEMA gitea OWNER TO %[3]s;
GRANT CONNECT ON DATABASE %[5]s TO %[3]s;
`, conn.AppUser, conn.AppPassword, conn.GiteaUser, conn.GiteaPassword, conn.Database)

	cmd := []string{
		"sh", "-c",
		fmt.Sprintf("PGPASSWORD=%q psql -v ON_ERROR_STOP=1 -U %s -d %s -c %q",
			conn.OwnerPassword, conn.OwnerUser, conn.Database, sql),
	}
	code, out, err := dx.Exec(ctx, SvcPostgres, cmd)
	if err != nil {
		return fmt.Errorf("db init exec: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("db init failed (exit %d): %s", code, out)
	}
	return nil
}
