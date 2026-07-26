// Package deploy turns a desired-state into concrete container specs. It is a pure spec
// factory + env renderer; the agent loop sequences the actual Docker actions. There is no
// compose file — the topology below IS the source of truth, computed from mode + add-ons.
package deploy

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/secrets"
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
	SSLMode       string
}

// DirectURL is the owner connection string used for migrations + grants + Gitea schema.
func (d DBConn) DirectURL() string {
	return fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=%s",
		d.OwnerUser, d.OwnerPassword, d.Host, d.Port, d.Database, d.SSLMode)
}

// ManagedDBConn builds the connection for the containerized Postgres (agent-generated creds).
func ManagedDBConn(m *secrets.Machine) DBConn {
	return DBConn{
		Host:          SvcPostgres,
		Port:          "5432",
		Database:      "vritti_core",
		AppUser:       "vritti_core_app",
		AppPassword:   m.DBAppPassword,
		OwnerUser:     "vritti_core_owner",
		OwnerPassword: m.DBOwnerPassword,
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
	return DBConn{
		Host:          e.Host,
		Port:          e.Port,
		Database:      e.Database,
		AppUser:       e.AppUser,
		AppPassword:   e.AppPassword,
		OwnerUser:     e.OwnerUser,
		OwnerPassword: e.OwnerPassword,
		SSLMode:       e.SSLMode,
	}, nil
}

// ResolveDBConn returns the DBConn for the deployment's mode. For external mode the caller
// supplies the already-decrypted sealed secret bytes.
func ResolveDBConn(ds cloudapi.DesiredState, m *secrets.Machine, externalSecret []byte) (DBConn, error) {
	if ds.Mode == cloudapi.ModeExternal {
		return ExternalDBConn(externalSecret)
	}
	return ManagedDBConn(m), nil
}

// Dirs returns the host bind-mount directories that must exist before containers start.
func Dirs(stackRoot string, ds cloudapi.DesiredState) []string {
	dirs := []string{
		filepath.Join(stackRoot, "logs"),
	}
	if ds.Mode == cloudapi.ModeManaged {
		dirs = append(dirs, filepath.Join(stackRoot, "pgdata"))
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
