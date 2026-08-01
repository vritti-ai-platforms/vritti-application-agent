package deploy

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/dockerx"
)

const mib = int64(1) << 20

// wget-based HTTP healthcheck for the node services.
func httpHealth(port int) *dockerx.HealthSpec {
	url := fmt.Sprintf("http://localhost:%d/", port)
	return &dockerx.HealthSpec{
		Test:     []string{"CMD", "wget", "-q", "--spider", url},
		Interval: 30 * time.Second,
		Timeout:  10 * time.Second,
		Retries:  3,
		Start:    40 * time.Second,
	}
}

// PostgresSpec is the containerized Postgres (managed mode only). Pinned major, bind-mounted data.
//
// The image ALWAYS carries the pgBackRest binary; it's dormant unless `archiving` is set. When
// the premium backup add-on is on we flip archive_mode=on + archive_command via the postgres
// command args and mount the pgbackrest config + local repo. Because archive_mode isn't
// reloadable, toggling this changes the spec hash and the reconciler recreates the container
// (a brief, deliberate restart) — which is exactly the required behavior.
func PostgresSpec(ds cloudapi.DesiredState, conn DBConn, stackRoot string, archiving bool) dockerx.RunSpec {
	// The container superuser IS the owner (matches local: POSTGRES_USER=vritti_core_owner).
	binds := []string{PostgresDataDir(stackRoot) + ":/var/lib/postgresql/data"}
	var cmd []string
	if archiving {
		binds = append(binds,
			filepath.Join(stackRoot, "pgbackrest")+":/etc/pgbackrest:ro",
			filepath.Join(stackRoot, "backup")+":/var/lib/pgbackrest",
		)
		cmd = []string{
			"postgres",
			"-c", "archive_mode=on",
			"-c", "archive_command=pgbackrest --stanza=" + StanzaName + " archive-push %p",
			"-c", "archive_timeout=60",
			"-c", "max_wal_size=1GB",
		}
	}
	return dockerx.RunSpec{
		Name:    SvcPostgres,
		Service: SvcPostgres,
		Image:   ds.Images.Postgres,
		Env: []string{
			"POSTGRES_USER=" + conn.OwnerUser,
			"POSTGRES_PASSWORD=" + conn.OwnerPassword,
			"POSTGRES_DB=" + conn.Database,
			"PGDATA=/var/lib/postgresql/data/pgdata",
		},
		Cmd:          cmd,
		Binds:        binds,
		ExposedPorts: []string{"5432/tcp"},
		Network:      Network,
		Restart:      true,
		MemLimit:     512 * mib,
		Health: &dockerx.HealthSpec{
			Test:     []string{"CMD-SHELL", "pg_isready -U " + conn.OwnerUser + " -d " + conn.Database},
			Interval: 10 * time.Second,
			Timeout:  5 * time.Second,
			Retries:  5,
			Start:    20 * time.Second,
		},
	}
}

// RedisSpec is the shared Redis, password supplied from the `/agent` provisioning creds.
func RedisSpec(ds cloudapi.DesiredState, redisPassword string) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:    SvcRedis,
		Service: SvcRedis,
		Image:   ds.Images.Redis,
		Cmd: []string{
			"redis-server",
			"--maxmemory", "128mb",
			"--maxmemory-policy", "allkeys-lru",
			"--save", "",
			"--requirepass", redisPassword,
		},
		ExposedPorts: []string{"6379/tcp"},
		Network:      Network,
		Restart:      true,
		MemLimit:     160 * mib,
	}
}

// NatsSpec is the internal NATS server (never published).
func NatsSpec(ds cloudapi.DesiredState) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:         SvcNats,
		Service:      SvcNats,
		Image:        ds.Images.Nats,
		ExposedPorts: []string{"4222/tcp"},
		Network:      Network,
		Restart:      true,
		MemLimit:     96 * mib,
	}
}

// CoreServerSpec is the core-server HTTP API.
func CoreServerSpec(ds cloudapi.DesiredState, env []string, stackRoot string) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:         SvcCore,
		Service:      SvcCore,
		Image:        ds.Images.CoreServer,
		Env:          env,
		Binds:        []string{filepath.Join(stackRoot, "logs", "core") + ":/app/logs"},
		ExposedPorts: []string{"3002/tcp"},
		Network:      Network,
		Restart:      true,
		MemLimit:     384 * mib,
		Health:       httpHealth(3002),
	}
}

// CommerceServiceSpec is the commerce microservice (NATS only, no HTTP).
func CommerceServiceSpec(ds cloudapi.DesiredState, env []string) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:     SvcCommerce,
		Service:  SvcCommerce,
		Image:    ds.Images.CommerceService,
		Env:      env,
		Network:  Network,
		Restart:  true,
		MemLimit: 256 * mib,
	}
}

// MigrateSpec is a one-shot Drizzle migration runner (owner conn applies migrations + grants).
func MigrateSpec(name, image string, env []string) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:    name,
		Service: name,
		Image:   image,
		Env:     env,
		Cmd:     []string{"node", "dist/db/migrate.js"},
		Network: Network,
	}
}

// GiteaSpec runs the Gitea server backed by the shared vritti_core DB in its own `gitea` schema.
func GiteaSpec(ds cloudapi.DesiredState, db DBConn, stackRoot string) dockerx.RunSpec {
	domain := "git." + ds.BaseDomain
	env := []string{
		"GITEA__database__DB_TYPE=postgres",
		fmt.Sprintf("GITEA__database__HOST=%s:%s", db.Host, db.Port),
		"GITEA__database__NAME=" + db.Database,
		"GITEA__database__USER=" + db.GiteaUser,
		"GITEA__database__PASSWD=" + db.GiteaPassword,
		"GITEA__database__SCHEMA=gitea",
		"GITEA__database__SSL_MODE=" + db.SSLMode,
		"GITEA__server__DOMAIN=" + domain,
		"GITEA__server__ROOT_URL=" + fmt.Sprintf("https://%s/", domain),
		"GITEA__server__HTTP_PORT=3000",
		"GITEA__server__SSH_PORT=2222",
		"GITEA__server__START_SSH_SERVER=true",
		"GITEA__security__INSTALL_LOCK=true",
		"GITEA__service__DISABLE_REGISTRATION=true",
	}
	return dockerx.RunSpec{
		Name:         SvcGitea,
		Service:      SvcGitea,
		Image:        ds.Images.Gitea,
		Env:          env,
		Binds:        []string{filepath.Join(stackRoot, "gitea") + ":/data"},
		ExposedPorts: []string{"3000/tcp"},
		Ports:        map[string]string{"2222/tcp": "2222"}, // git SSH published for clones
		Network:      Network,
		Restart:      true,
		MemLimit:     256 * mib,
		Health: &dockerx.HealthSpec{
			Test:     []string{"CMD", "wget", "-q", "--spider", "http://localhost:3000/api/healthz"},
			Interval: 15 * time.Second,
			Timeout:  10 * time.Second,
			Retries:  5,
			Start:    30 * time.Second,
		},
	}
}

// Backups are NOT a standalone sidecar: a separate container can't run archive_command (that's
// in the Postgres process) and a local-mode `pgbackrest backup` needs the Postgres container's
// data dir + local socket. So both archiving and scheduled backups run INSIDE the Postgres
// container — archive_command continuously, and `pgbackrest backup` via `docker exec` on the
// agent's schedule (see pgbackrest.go). There is no pgbackrest container to manage.

// NginxSpec is the managed edge (Edge=managed). It serves conf.d/vritti.conf, reads Let's Encrypt
// certs from the shared letsencrypt dir, and serves the ACME webroot for HTTP-01 renewals.
func NginxSpec(ds cloudapi.DesiredState, stackRoot string) dockerx.RunSpec {
	return dockerx.RunSpec{
		Name:    SvcNginx,
		Service: SvcNginx,
		Image:   ds.Images.Nginx,
		Binds: []string{
			filepath.Join(stackRoot, "nginx", "conf.d") + ":/etc/nginx/conf.d:ro",
			filepath.Join(stackRoot, leDir) + ":/etc/letsencrypt:ro",
			filepath.Join(stackRoot, leDir, "www") + ":/var/www/letsencrypt:ro",
			filepath.Join(stackRoot, "logs", "nginx") + ":/var/log/nginx",
		},
		Ports:    map[string]string{"80/tcp": "80", "443/tcp": "443"},
		Network:  Network,
		Restart:  true,
		MemLimit: 96 * mib,
	}
}
