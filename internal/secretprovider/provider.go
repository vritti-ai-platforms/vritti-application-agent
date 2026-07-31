// Package secretprovider is the agent's pluggable secret store. The concrete backend and its
// connection + auth config are NOT baked into the agent — they arrive per-reconcile in the
// cloud-signed desired-state (cloudapi.SecretProvider), and the SECRET half of the auth method
// arrives on the SealedSecrets channel. The agent hardcodes nothing store-specific: it constructs
// a Provider from that config and reads each service's env through the generic Fetch below.
package secretprovider

import "context"

// Provider reads a folder of key→value secrets from a backing secret store.
type Provider interface {
	// Fetch returns the merged key→value map for a folder path (imports merged, references expanded).
	Fetch(ctx context.Context, path string) (map[string]string, error)
}
