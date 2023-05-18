package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenidConfig(t *testing.T) {
	bs := &BearerServer{}
	req, err := http.NewRequest("GET", "/openid-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.OpenidConfig)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := `{"issuer":"http://example.com","authorization_endpoint":"http://example.com/oauth/authorize","token_endpoint":"http://example.com/oauth/token","introspection_endpoint":"http://example.com/oauth/introspect","userinfo_endpoint":"http://example.com/oauth/userinfo","registration_endpoint":"http://example.com/oauth/clients","jwks_uri":"http://example.com/oauth/keys","revocation_endpoint":"http://example.com/oauth/revoke","scopes_supported":["api","read_api","read_user","read_repository","write_repository","read_registry","write_registry","sudo","openid","profile","email"],"response_types_supported":["code"],"response_modes_supported":["query","fragment"],"grant_types_supported":["authorization_code","password","client_credentials","refresh_token"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"claims_supported":["iss","sub","aud","exp","iat","sub_legacy","name","nickname","email","email_verified","website","profile","picture","groups","groups_direct"]}`

	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}
