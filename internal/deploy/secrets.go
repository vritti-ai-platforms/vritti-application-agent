package deploy

import (
	"fmt"
	"sort"
	"strings"
)

// RequireSecrets returns an error naming every key that's absent or blank in env, so a missing secret fails
// the reconcile up front with an actionable message (which folder + which keys) instead of silently
// provisioning blanks. folder is the secret-store path (e.g. "/agent/postgres") used in the message.
func RequireSecrets(folder string, env map[string]string, keys ...string) error {
	var missing []string
	for _, k := range keys {
		if strings.TrimSpace(env[k]) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("missing required %s secrets: %s", folder, strings.Join(missing, ", "))
}
