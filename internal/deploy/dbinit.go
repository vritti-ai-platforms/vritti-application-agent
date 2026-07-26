package deploy

import (
	"context"
	"fmt"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secrets"
)

// EnsureManagedDatabase provisions the roles + schemas the app expects inside the containerized
// Postgres, idempotently, by exec'ing psql in the running postgres container as the superuser.
//
//   - vritti_core_owner  → owns the database + schemas; migrations run as this role
//   - vritti_core_app    → least-privilege runtime login the services use
//   - schema `gitea`     → Gitea's metadata lives beside core/commerce in one database
//
// The core/commerce schemas themselves are created by the Drizzle migrate runner (as owner).
func EnsureManagedDatabase(ctx context.Context, dx *dockerx.Client, m *secrets.Machine) error {
	conn := ManagedDBConn(m)
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
ALTER DATABASE %[5]s OWNER TO %[1]s;
CREATE SCHEMA IF NOT EXISTS gitea AUTHORIZATION %[1]s;
`, conn.OwnerUser, conn.OwnerPassword, conn.AppUser, conn.AppPassword, conn.Database)

	cmd := []string{
		"sh", "-c",
		fmt.Sprintf("PGPASSWORD=%q psql -v ON_ERROR_STOP=1 -U postgres -d %s -c %q",
			m.PostgresSuperPassword, conn.Database, sql),
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
