package deploy

import "sort"

// RenderCoreEnv turns core-server's Infisical map into its container env, injected verbatim, and
// (when the Gitea add-on is on) appends the base URL + minted admin token so core can create the
// app git user + PAT. The map already holds only what core reads (PRIMARY_DB_*, REDIS_URL, R2_*,
// the app crypto secrets, etc.) — the raw provisioning creds live in the `/agent` folder, not
// here, so there is nothing to strip. The same rendering feeds both the migrate runner and the
// long-running container (the migrate call passes empty gitea args).
//
// BASE_DOMAIN + REFRESH_COOKIE_DOMAIN are OVERRIDDEN with the desired-state's baseDomain (a bare
// hostname like sheshu.vrittiai.com). core-server derives the tenant subdomain via
// host.endsWith('.'+BASE_DOMAIN), which needs a scheme-less host — operators who set
// BASE_DOMAIN=https://… in Infisical would otherwise break subdomain resolution ("org not found").
// The agent is authoritative here, so cloud's canonical base domain always wins.
func RenderCoreEnv(coreEnv map[string]string, baseDomain, giteaURL, giteaToken string) []string {
	env := make(map[string]string, len(coreEnv)+2)
	for k, v := range coreEnv {
		env[k] = v
	}
	if baseDomain != "" {
		env["BASE_DOMAIN"] = baseDomain
		env["REFRESH_COOKIE_DOMAIN"] = baseDomain
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
