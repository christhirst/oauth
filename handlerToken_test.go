package oauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/christhirst/gohelper/iasserts"
	"github.com/go-chi/chi/v5"
)

func TestTokenEndpoint(t *testing.T) {
	req, err := http.NewRequest("POST", "/oauth/clients", nil)
	if err != nil {
		t.Errorf("json encoding failed %v", err)
	}
	form := url.Values{}
	req.Form = form
	form.Add("grant_type", "authorization_code")
	form.Add("code", "test")
	form.Add("redirect_uri", "http://localhost:8080")

	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("clientID:TestSecret")))
	rr := httptest.NewRecorder()

	bs := NewBearerServer(
		"mySecretKey-10101",
		time.Second*120,
		&TestUserVerifier{},
		nil,
	)
	handler := http.HandlerFunc(bs.TokenEndpoint)
	handler.ServeHTTP(rr, req)

	//clientId := []string{"clientID"}
	//token, refreshToken, idtoken, err := bs.generateIdTokens("RS256", clientId, UserToken, "user111", "test", []string{"group1"}, at, req)

	//t.Error(token)

	/* 	t.Run("TokenEndPoint Test 1", func(t *testing.T) {
	   		iasserts.AssertNoError(t, err)
	   	})
	   	t.Run("TokenEndPoint Test 2", func(t *testing.T) {
	   		iasserts.AssertEmptyString(t, token)
	   	})
	   	t.Run("TokenEndPoint Test 3", func(t *testing.T) {
	   		iasserts.AssertEmptyString(t, idtoken)
	   	})
	   	t.Run("TokenEndPoint Test 4", func(t *testing.T) {
	   		iasserts.AssertString(t, refreshToken.TokenID, clientId[0])
	   	}) */

}

func TestTokenIntrospect(t *testing.T) {
	//var at AuthToken
	t.Run("Get jwt from Header", func(t *testing.T) {
		//req, _ := http.NewRequest("POST", "/oauth/introspect", nil)
		mux := chi.NewRouter()
		mux.Post("/oauth/introspect", bs.TokenIntrospect)
		//ts := httptest.NewTLSServer(mux)
		/* groups := []string{"group1", "group2"}
		scope := []string{"scope1", "scope2"}
		aud := []string{"scope1"} */
		//claims := bs.Verifier.CreateAtClaims("TestclientID", "username", aud, bs.nonce, scope, groups, at, req)

		//access_token, _ := CreateJWT("RS256", claims, bs.Kc)
		//dd := url.Values{"token": {access_token}}
		//resp, err := ts.Client().PostForm(ts.URL+"/oauth/introspect", dd)
		/* if err != nil {
			t.Errorf("json encoding failed %v", err)
		}
		obj := make(map[string]interface{})
		ConvertIOReader(resp.Body, &obj)
		for i, v := range obj {
			if (i != "sub") && (i != "iat") && (i != "iss") && (i != "jti") && (i != "active") && (i != "scope") && (i != "client_id") {
				if i == "active" && v != true {
					t.Error(err)
				}
			}
		} */
	})

	t.Run("Get jwt from Header", func(t *testing.T) {
		mux := chi.NewRouter()
		mux.Post("/oauth/introspect", bs.TokenIntrospect)
		ts := httptest.NewTLSServer(mux)
		dd := url.Values{"token": {"test", "test2"}}
		_, err := ts.Client().PostForm(ts.URL+"/oauth/introspect", dd)
		if err != nil {
			t.Errorf("json encoding failed %v", err)
		}

	})

}

func TestTokenRevocation(t *testing.T) {
	get := map[string]string{"token": "", "refresh_token": "", "access_token": ""}
	empJSON, err := json.Marshal(get)
	if err != nil {
		log.Fatalf(err.Error())
	}

	req, err := http.NewRequest("POST", "/oauth/revoke", bytes.NewBuffer(empJSON))
	if err != nil {
		t.Errorf("json encoding failed %v", err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password123456")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rw := httptest.NewRecorder()
	bs.TokenRevocation(rw, req)
	got := rw.Code
	want := 200

	t.Run("TokenEndPoint Test 1", func(t *testing.T) {
		iasserts.AssertResponseCode(t, want, got)
	})
}
