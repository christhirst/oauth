package oauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/christhirst/gohelper/iasserts"
)

func TestOpenidConfigHandler(t *testing.T) {
	// Create a new request with a GET method and a nil body
	req, err := http.NewRequest("GET", "/openid-config", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set the Host field of the request to "example.com"
	req.Host = "example.com"

	// Create a new response recorder to capture the response
	rr := httptest.NewRecorder()

	// Create a new BearerServer instance
	bs := &BearerServer{}

	// Call the OpenidConfig handler function with the response recorder and request
	handler := http.HandlerFunc(bs.OpenidConfig)
	handler.ServeHTTP(rr, req)

	// Check the status code of the response
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the content type of the response
	if ctype := rr.Header().Get("Content-Type"); ctype != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want %v", ctype, "application/json")
	}

	body, err := ioutil.ReadAll(rr.Body)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	var got OpenidConfig
	err = json.Unmarshal(body, &got)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Check the body of the response
	expected := `{"issuer":"https://example.com","authorization_endpoint":"https://example.com/oauth/authorize",
	"token_endpoint":"https://example.com/oauth/token","introspection_endpoint":"https://example.com/oauth/introspect",
	"userinfo_endpoint":"https://example.com/oauth/userinfo","registration_endpoint":"https://example.com/oauth/clients",
	"jwks_uri":"https://example.com/oauth/keys","revocation_endpoint":"https://example.com/oauth/revoke",
	"scopes_supported":["api","read_api","read_user","read_repository","write_repository","read_registry","write_registry","sudo",
	"openid","profile","email"],"response_types_supported":["code"],"response_modes_supported":["query","fragment"],
	"grant_types_supported":["authorization_code","password","client_credentials","refresh_token"],
	"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"subject_types_supported":["public"],
	"id_token_signing_alg_values_supported":["RS256"],"claims_supported":["iss","sub","aud","exp","iat","sub_legacy","name","nickname",
	"email","email_verified","website","profile","picture","groups","groups_direct"]}`

	var want OpenidConfig
	err = json.Unmarshal([]byte(expected), &want)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("%+v\n", want)

	iasserts.AssertNotComparable(t, got, want)
}
