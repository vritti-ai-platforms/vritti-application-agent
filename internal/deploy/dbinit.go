package deploy

import (
	"context"
	"fmt"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/config"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

// EnsureManagedDatabase provisions the roles + schemas the app expects inside the containerized
// Postgres, idempotently, by exec'ing psql in the running postgres container as the superuser.
//
//   - vritti_core_owner  → owns the database + schemas; migrations run as this role
//   - vritti_core_app    → least-privilege runtime login the services use
//   - gitea              → least-privilege login that owns ONLY the `gitea` schema (no access
//     to core/commerce); Gitea connects as this role, sharing the DB without owner reach
//
// The core/commerce schemas themselves are created by the Drizzle migrate runner (as owner).
func EnsureManagedDatabase(ctx context.Context, dx *dockerx.Client, cfg *config.Config) error {
	conn := ManagedDBConn(cfg)
	sql := fmt.Sprintf(`
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='%[1]s') THEN
    CREATE ROLE %[1]s LOGIN PASSWORD '%[2]s';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='%[3]s') THEN
    CREATE ROLE %[3]s LOGIN PASSWORD '%[4]s';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='%[6]s') THEN
    CREATE ROLE %[6]s LOGIN PASSWORD '%[7]s';
  END IF;
END $$;
ALTER ROLE %[1]s WITH PASSWORD '%[2]s';
ALTER ROLE %[3]s WITH PASSWORD '%[4]s';
ALTER ROLE %[6]s WITH PASSWORD '%[7]s';
ALTER DATABASE %[5]s OWNER TO %[1]s;
CREATE SCHEMA IF NOT EXISTS gitea AUTHORIZATION %[6]s;
ALTER SCHEMA gitea OWNER TO %[6]s;
GRANT CONNECT ON DATABASE %[5]s TO %[6]s;
`, conn.OwnerUser, conn.OwnerPassword, conn.AppUser, conn.AppPassword, conn.Database, conn.GiteaUser, conn.GiteaPassword)

	cmd := []string{
		"sh", "-c",
		fmt.Sprintf("PGPASSWORD=%q psql -v ON_ERROR_STOP=1 -U postgres -d %s -c %q",
			cfg.PostgresSuperPassword, conn.Database, sql),
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
