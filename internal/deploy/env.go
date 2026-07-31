package deploy

import "sort"

// RenderCoreEnv turns core-server's Infisical map into its container env, injected verbatim, and
// (when the Gitea add-on is on) appends the base URL + minted admin token so core can create the
// app git user + PAT. The map already holds only what core reads (PRIMARY_DB_*, REDIS_URL, R2_*,
// the app crypto secrets, etc.) — the raw provisioning creds live in the `/agent` folder, not
// here, so there is nothing to strip. The same rendering feeds both the migrate runner and the
// long-running container (the migrate call passes empty gitea args).
func RenderCoreEnv(coreEnv map[string]string, giteaURL, giteaToken string) []string {
	env := make(map[string]string, len(coreEnv)+2)
	for k, v := range coreEnv {
		env[k] = v
	}
	if giteaURL != "" {
		env["GITEA_BASE_URL"] = giteaURL
		env["GITEA_ADMIN_TOKEN"] = giteaToken
	}
	return mapToSortedSlice(env)
}

// RenderServiceEnv turns commerce-service's Infisical map into its container env, verbatim.
func RenderServiceEnv(commerceEnv map[string]string) []string {
	return mapToSortedSlice(commerceEnv)
}

// mapToSortedSlice converts a map into a deterministic KEY=VALUE slice (sorted for stable spec hashes).
func mapToSortedSlice(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}
