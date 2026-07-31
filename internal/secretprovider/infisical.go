// Infisical Provider. Built entirely from the cloud-supplied cloudapi.SecretProvider (URL, project,
// env, auth method + non-secret params) plus the decrypted sealed auth secrets — nothing Infisical-
// or company-specific is hardcoded here. Uses the official Go SDK (github.com/infisical/go-sdk),
// supporting every machine-identity auth method the SDK exposes, dispatched on Auth.Method.
package secretprovider

import (
	"context"
	"fmt"

	infisical "github.com/infisical/go-sdk"
	"github.com/vritti-ai-platforms/vritti-application-agent/internal/cloudapi"
)

// userAgent is a non-default UA so requests survive the self-hosted Infisical's Cloudflare edge,
// which 1010-blocks known bot UAs (including the SDK's default).
const userAgent = "vritti-application-agent"

// infisicalProvider is an authenticated SDK client bound to one project + environment.
type infisicalProvider struct {
	client    infisical.InfisicalClientInterface
	projectID string
	env       string
}

// New builds a Provider from the cloud-signed secret-store config and the decrypted sealed auth
// secrets (keyed by the reserved names: clientSecret, token, jwt, password, serviceAccountToken,
// privateKey, passphrase). It dispatches on sp.Type (only "infisical" today) then on the auth method.
func New(ctx context.Context, sp cloudapi.SecretProvider, authSecrets map[string]string) (Provider, error) {
	switch sp.Type {
	case "infisical":
		return newInfisical(ctx, sp, authSecrets)
	default:
		return nil, fmt.Errorf("unsupported secret provider type %q", sp.Type)
	}
}

// newInfisical constructs the SDK client, authenticates it via the configured method, and returns
// a Provider ready to Fetch. Auto token refresh is on so a long-lived agent keeps a valid token.
func newInfisical(ctx context.Context, sp cloudapi.SecretProvider, authSecrets map[string]string) (Provider, error) {
	autoRefresh := true
	client := infisical.NewInfisicalClient(ctx, infisical.Config{
		SiteUrl:          sp.URL,
		AutoTokenRefresh: &autoRefresh,
		SilentMode:       true,
		UserAgent:        userAgent,
	})

	if err := authenticate(client, sp.Auth, authSecrets); err != nil {
		return nil, err
	}
	return &infisicalProvider{client: client, projectID: sp.ProjectID, env: sp.Env}, nil
}

// authenticate logs the client in using the desired-state's auth method. Non-secret inputs come
// from auth.Params; the secret half comes from authSecrets (the decrypted sealed values).
func authenticate(client infisical.InfisicalClientInterface, auth cloudapi.SecretProviderAuth, secrets map[string]string) error {
	p := auth.Params
	var err error
	switch auth.Method {
	case "universal":
		_, err = client.Auth().UniversalAuthLogin(p["clientId"], secrets["clientSecret"])
	case "token":
		// No login round-trip — the caller supplied a ready access token.
		client.Auth().SetAccessToken(secrets["token"])
	case "aws-iam":
		_, err = client.Auth().AwsIamAuthLogin(p["identityId"])
	case "gcp-id-token":
		_, err = client.Auth().GcpIdTokenAuthLogin(p["identityId"])
	case "gcp-iam":
		_, err = client.Auth().GcpIamAuthLogin(p["identityId"], p["serviceAccountKeyFilePath"])
	case "azure":
		_, err = client.Auth().AzureAuthLogin(p["identityId"], p["resource"])
	case "kubernetes":
		_, err = client.Auth().KubernetesAuthLogin(p["identityId"], p["serviceAccountTokenPath"])
	case "kubernetes-token":
		_, err = client.Auth().KubernetesRawServiceAccountTokenLogin(p["identityId"], secrets["serviceAccountToken"])
	case "oidc":
		_, err = client.Auth().OidcAuthLogin(p["identityId"], secrets["jwt"])
	case "jwt":
		_, err = client.Auth().JwtAuthLogin(p["identityId"], secrets["jwt"])
	case "ldap":
		_, err = client.Auth().LdapAuthLogin(p["identityId"], p["username"], secrets["password"])
	case "oci":
		_, err = client.Auth().OciAuthLogin(infisical.OciAuthLoginOptions{
			IdentityID:  p["identityId"],
			PrivateKey:  secrets["privateKey"],
			Fingerprint: p["fingerprint"],
			UserID:      p["userId"],
			TenancyID:   p["tenancyId"],
			Region:      p["region"],
			Passphrase:  optPtr(secrets["passphrase"]),
		})
	default:
		return fmt.Errorf("unsupported infisical auth method %q", auth.Method)
	}
	if err != nil {
		return fmt.Errorf("infisical %s auth: %w", auth.Method, err)
	}
	return nil
}

// Fetch lists the folder's secrets with references expanded and imports merged (folder wins), and
// flattens them to a key→value map. The SDK's List already folds IncludeImports secrets into the
// returned slice (own key wins over an imported one), so no extra merge is needed here.
func (i *infisicalProvider) Fetch(ctx context.Context, path string) (map[string]string, error) {
	secrets, err := i.client.Secrets().List(infisical.ListSecretsOptions{
		ProjectID:              i.projectID,
		Environment:            i.env,
		SecretPath:             path,
		ExpandSecretReferences: true,
		IncludeImports:         true,
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(secrets))
	for _, s := range secrets {
		out[s.SecretKey] = s.SecretValue
	}
	return out, nil
}

// optPtr returns a pointer to v, or nil when v is empty (for the SDK's optional *string fields).
func optPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
