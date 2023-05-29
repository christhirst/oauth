package oauth

import (
	"fmt"
	"net/http"
)

func (bs *BearerServer) OpenidConfig(w http.ResponseWriter, r *http.Request) {
	baseURL := scheme + r.Host
	j := OpenidConfig{
		Issuer:                                fmt.Sprintf("%s/oauth", baseURL),
		Authorization_endpoint:                fmt.Sprintf("%s/oauth/authorize", baseURL),
		Token_endpoint:                        fmt.Sprintf("%s/oauth/token", baseURL),
		Introspection_endpoint:                fmt.Sprintf("%s/oauth/introspect", baseURL),
		Userinfo_endpoint:                     fmt.Sprintf("%s/oauth/userinfo", baseURL),
		Registration_endpoint:                 fmt.Sprintf("%s/oauth/clients", baseURL),
		Jwks_uri:                              fmt.Sprintf("%s/oauth/keys", baseURL),
		Revocation_endpoint:                   fmt.Sprintf("%s/oauth/revoke", baseURL),
		Scopes_supported:                      []string{"api", "read_api", "read_user", "read_repository", "write_repository", "read_registry", "write_registry", "sudo", "openid", "profile", "email"},
		Response_types_supported:              []string{"code"},
		Response_modes_supported:              []string{"query", "fragment"},
		Grant_types_supported:                 []string{"authorization_code", "password", "client_credentials", "refresh_token"},
		Token_endpoint_auth_methods_supported: []string{"client_secret_basic", "client_secret_post"},
		Subject_types_supported:               []string{"public"},
		Id_token_signing_alg_values_supported: []string{"RS256"},
		Claims_supported:                      []string{"iss", "sub", "aud", "exp", "iat", "sub_legacy", "name", "nickname", "email", "email_verified", "website", "profile", "picture", "groups", "groups_direct"},
	}
	renderJSON(w, j, http.StatusOK)
}

/* func (bs *BearerServer) Jwk(w http.ResponseWriter, r *http.Request) {
	renderJSON(w, nil, http.StatusOK)
}
*/
