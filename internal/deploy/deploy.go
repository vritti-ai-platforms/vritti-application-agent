// Package deploy turns a desired-state into concrete container specs. It is a pure spec
// factory + env renderer; the agent loop sequences the actual Docker actions. There is no
// compose file — the topology below IS the source of truth, computed from mode + add-ons.
package deploy

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
)

// Network is the private bridge every service in a core deployment shares.
const Network = "vritti-core-net"

// Fixed service names (also the container names — one deployment per host).
const (
	SvcPostgres = "postgres"
	SvcRedis    = "redis"
	SvcNats     = "nats"
	SvcCore     = "core-server"
	SvcCommerce = "commerce-service"
	SvcGitea    = "gitea"
	SvcNginx    = "nginx"
)

// DBConn is the resolved database connection for the current mode.
type DBConn struct {
	Host          string
	Port          string
	Database      string
	AppUser       string
	AppPassword   string
	OwnerUser     string
	OwnerPassword string
	GiteaUser     string
	GiteaPassword string
	SSLMode       string
}

// DirectURL is the owner connection string used for migrations + grants + Gitea schema.
func (d DBConn) DirectURL() string {
	return fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=%s",
		d.OwnerUser, d.OwnerPassword, d.Host, d.Port, d.Database, d.SSLMode)
}

// ManagedProvisioning are the raw data-store creds the agent uses to stand up managed Postgres +
// Redis. They come from Infisical's `/agent` folder (never generated, never seen by cloud) and are
// threaded through the reconcile rather than read from cfg.
type ManagedProvisioning struct {
	DBName        string // per-deployment DB name (defaults to vritti_core when empty)
	OwnerPassword string // vritti_core_owner — the container superuser + migration role
	AppPassword   string // vritti_core_app — least-privilege runtime login
	GiteaPassword string // gitea — least-privilege login owning only the gitea schema
	RedisPassword string
}

// database returns the configured DB name, defaulting to vritti_core.
func (p ManagedProvisioning) database() string {
	if p.DBName == "" {
		return "vritti_core"
	}
	return p.DBName
}

// ManagedDBConn builds the connection for the containerized Postgres from the provisioning creds.
func ManagedDBConn(p ManagedProvisioning) DBConn {
	return DBConn{
		Host:          SvcPostgres,
		Port:          "5432",
		Database:      p.database(),
		AppUser:       "vritti_core_app",
		AppPassword:   p.AppPassword,
		OwnerUser:     "vritti_core_owner",
		OwnerPassword: p.OwnerPassword,
		GiteaUser:     "gitea",
		GiteaPassword: p.GiteaPassword,
		SSLMode:       "disable",
	}
}

// ExternalDB is the shape of the sealed "external_db" secret the operator provides in external mode.
type ExternalDB struct {
	Host          string `json:"host"`
	Port          string `json:"port"`
	Database      string `json:"database"`
	OwnerUser     string `json:"ownerUser"`
	OwnerPassword string `json:"ownerPassword"`
	AppUser       string `json:"appUser"`
	AppPassword   string `json:"appPassword"`
	GiteaUser     string `json:"giteaUser"`
	GiteaPassword string `json:"giteaPassword"`
	SSLMode       string `json:"sslMode"`
}

// ExternalDBConn parses the decrypted external-db secret JSON into a DBConn.
func ExternalDBConn(decrypted []byte) (DBConn, error) {
	var e ExternalDB
	if err := json.Unmarshal(decrypted, &e); err != nil {
		return DBConn{}, fmt.Errorf("parse external_db secret: %w", err)
	}
	if e.Port == "" {
		e.Port = "5432"
	}
	if e.SSLMode == "" {
		e.SSLMode = "require"
	}
	if e.GiteaUser == "" {
		e.GiteaUser = "gitea"
	}
	return DBConn{
		Host:          e.Host,
		Port:          e.Port,
		Database:      e.Database,
		AppUser:       e.AppUser,
		AppPassword:   e.AppPassword,
		OwnerUser:     e.OwnerUser,
		OwnerPassword: e.OwnerPassword,
		GiteaUser:     e.GiteaUser,
		GiteaPassword: e.GiteaPassword,
		SSLMode:       e.SSLMode,
	}, nil
}

// ResolveDBConn returns the DBConn for the deployment's mode. Managed mode uses the provisioning
// creds from Infisical's `/agent` folder; external mode parses the already-decrypted sealed secret.
func ResolveDBConn(ds cloudapi.DesiredState, prov ManagedProvisioning, externalSecret []byte) (DBConn, error) {
	if ds.Mode == cloudapi.ModeExternal {
		return ExternalDBConn(externalSecret)
	}
	return ManagedDBConn(prov), nil
}

// PostgresUID is the uid the official postgres image runs as. Its bind-mounted data dir must be
// owned by this uid or initdb fails with "Permission denied" on the root-owned mount.
const PostgresUID = 999

// PostgresDataDir is the host bind-mount dir for the managed Postgres data (mounted at
// /var/lib/postgresql/data; PGDATA is the `pgdata` subdir inside it).
func PostgresDataDir(stackRoot string) string { return filepath.Join(stackRoot, "pgdata") }

// Dirs returns the host bind-mount directories that must exist before containers start.
func Dirs(stackRoot string, ds cloudapi.DesiredState) []string {
	dirs := []string{
		filepath.Join(stackRoot, "logs"),
	}
	if ds.Mode == cloudapi.ModeManaged {
		dirs = append(dirs, PostgresDataDir(stackRoot))
		if ds.AddOns.PgBackRest {
			dirs = append(dirs,
				filepath.Join(stackRoot, "backup"),
				filepath.Join(stackRoot, "pgbackrest"),
			)
		}
	}
	if ds.AddOns.Gitea {
		dirs = append(dirs, filepath.Join(stackRoot, "gitea"))
	}
	return dirs
}
