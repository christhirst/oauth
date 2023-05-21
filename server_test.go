package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	ll "log"
	"net/http"
	"testing"
	"time"

	"github.com/christhirst/gohelper/iasserts"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/rs/zerolog/log"
)

var _sut = NewBearerServer(
	"mySecretKey-10101",
	time.Second*60,
	new(TestUserVerifier),
	nil,
)

func TestNewBearerServer(t *testing.T) {
	t.Run("Sign in Test no client_id", func(t *testing.T) {
		secretKey := "mySecretKey-10101"
		ttl := time.Second * 60
		Verifier := new(TestUserVerifier)
		server := NewBearerServer(secretKey, ttl, Verifier, nil)
		iasserts.AssertResponseCode(t, server.pKey.PublicKey.Size(), 256)
	})
}

type TestUserVerifier struct {
}

//func (*TestUserVerifier)CredentialsVerifier

func (*TestUserVerifier) StoreClient(clientname string, clientData Registration, methode string) (*Registration, error) {
	var respInterface map[string]interface{}
	inrec, err := json.Marshal(clientData)
	if err != nil {
		log.Err(err)
	}

	err = json.Unmarshal(inrec, &respInterface)
	if err != nil {
		log.Error().Err(err).Msg("Unable to Unmarshal file")
	}

	return nil, nil
}

func (*TestUserVerifier) StoreClientDelete(clientId []string) error {
	return nil
}

func (*TestUserVerifier) UserLookup(username string, scope []string) (map[string]string, []string, error) {
	return nil, nil, nil
}

/*
	 func (TestUserVerifier) AddIdClaims() (map[string]string, error) {
		return map[string]string{}, nil
	}
*/
func (TestUserVerifier) CreateClaims(username string, formData FormList, groups []string, r *http.Request) MyCustomClaimss {
	scheme := "https://"
	baseURL := scheme + r.Host

	claims := MyCustomClaimss{
		Nonce:  formData.Nonce,
		Groups: groups,
		Azp:    formData.ClientID,

		RegisteredClaims: jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    baseURL + "",
			Subject:   "somebody",
			ID:        "1",
			Audience:  at.Aud,
		},
	}
	return claims
}

/* func (TestUserVerifier) CreateAtClaims(client_id, username string, aud []string, nonce string, scope, groups []string, at AuthToken, r *http.Request) MyCustomClaimss {
	scheme := "https://"
	baseURL := scheme + r.Host
	claims := MyCustomClaimss{
		Client_id: client_id,
		Scope:     scope,
		RegisteredClaims: jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Second * 2)),
			Issuer:    baseURL + "",
			Subject:   "somebody",
			ID:        "1",
			Audience:  at.Aud,
		}}

	return claims
} */

// Validate username and password returning an error if the user credentials are wrong
func (TestUserVerifier) ValidateUser(username, password, scope string, r *http.Request) ([]string, error) {
	// Add something to the request context, so we can access it in the claims and props funcs.
	ctx := r.Context()
	ctx = context.WithValue(ctx, "claims.test", "test")
	ctx = context.WithValue(ctx, "props.test", "test")
	*r = *r.Clone(ctx)
	return []string{}, errors.New("")
}

func (TestUserVerifier) GetUserData(username, scope string, r *http.Request) (map[string]string, error) {
	// Add something to the request context, so we can access it in the claims and props funcs.
	return nil, nil
}

// Validate clientID and secret returning an error if the client credentials are wrong
func (TestUserVerifier) ValidateClient(clientID, clientSecret string) error {
	// Add something to the request context, so we can access it in the claims and props funcs.
	var r *http.Request
	ctx := r.Context()
	ctx = context.WithValue(ctx, "oauth.claims.test", "test")
	ctx = context.WithValue(ctx, "oauth.props.test", "test")
	*r = *r.Clone(ctx)

	if clientID == "abcdef" && clientSecret == "12345" {
		return nil
	}
	return errors.New("wrong client")
}

// Provide additional claims to the token
func (TestUserVerifier) AddClaims(tokenType TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error) {
	claims := make(map[string]string)
	claims["customer_id"] = "1001"
	claims["customer_data"] = `{"order_date":"2016-12-14","order_id":"9999"}`

	// Get value from request context, and add it to our claims.
	test := r.Context().Value("oauth.claims.test")
	if test != nil {
		claims["ctx_value"] = test.(string)
	}
	return claims, nil
}

// Provide additional information to the token response
func (TestUserVerifier) AddProperties(tokenType TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error) {
	props := make(map[string]string)
	props["customer_name"] = "Gopher"

	// Get value from request context, and add it to our props.
	test := r.Context().Value("oauth.props.test")
	if test != nil {
		props["ctx_value"] = test.(string)
	}
	return props, nil
}

// Validate token ID
func (TestUserVerifier) ExtractJWTtoUserGroup(jwt string) ([]string, error) {
	fmt.Println(jwt)
	fmt.Println("ee")
	groups := []string{"group1", "group2"}
	return groups, nil
}

// Optionally store the token ID generated for the user
func (TestUserVerifier) StoreTokenID(tokenType TokenType, credential, tokenID, refreshTokenID string) error {
	return nil
}

func (*TestUserVerifier) GetConnectionTarget(r *http.Request) (string, error) {
	return "false", nil
}

func (*TestUserVerifier) SessionGet(w http.ResponseWriter, r *http.Request, cookieID string) (string, bool, error) {
	cookies, err := r.Cookie(cookieID)
	if err == nil && cookies.Value == "testing" {
		fmt.Println(cookies)
	}
	return "testUser", true, nil
}

func (*TestUserVerifier) StoreClientsGet() (map[string]*Registration, error) {

	var Cjson = Registration{Client_id: "testid", Registration_access_token: "eeee", Client_name: "ee", Logo_uri: "",
		Contacts: []string{"ee"}, Application_type: "", Grant_types: "a", Response_types: "", Redirect_uris: []string{"wwewe"},
		Token_endpoint_auth_method: "w"}

	var respInterface map[string]interface{}
	inrec, _ := json.Marshal(Cjson)
	err := json.Unmarshal(inrec, &respInterface)
	if err != nil {
		log.Err(err)
	}
	return nil, nil
}

func (*TestUserVerifier) SessionSave(w http.ResponseWriter, r *http.Request, userID, cookieID string) (string, error) {
	cookies, err := r.Cookie(cookieID)
	if err == nil && cookies.Value == "testing" {
		fmt.Println(cookies)
	}
	return "", nil
}

func (*TestUserVerifier) StoreClientGet(client string) (*Registration, error) {
	ee := Registration{
		Client_id:     "testClientID",
		Client_secret: "testClientSecret",
		Kid:           "testKid",
		Redirect_uris: []string{
			"https://client.example.org/callback",
			"https://client.example.org/callback2",
		},
		Grant_types:                  "openid",
		Response_types:               "openid",
		Id_token_signed_response_alg: "rs256",
		Subject_type:                 "test",
		Application_type:             "web",
		Client_name:                  client,
		Logo_uri:                     "https://client.example.org/logo.png",
		Token_endpoint_auth_method:   "client_secret_basic",
		Contacts:                     []string{"admin@example.org"},
		Registration_access_token:    "testRegToken",
	}

	//	var respInterface *Registration
	//	inrec, _ := json.Marshal(ee)
	//	json.Unmarshal(inrec, &respInterface)
	return &ee, nil
}

func StoreClientDelete(client []string) {}

func (*TestUserVerifier) StoreKeyDelete(kid []string) error { return nil }
func (*TestUserVerifier) StoreKey(keyString map[string]string) error {
	fmt.Println("eese")
	return nil
}
func (*TestUserVerifier) StoreKeysGet() (map[string]rsa.PrivateKey, error) { return nil, nil }

func (*TestUserVerifier) StoreKeysAppend(jwks []map[string]string) []map[string]string {
	return jwks
}

func (*TestUserVerifier) SignInMethod(clientId string, w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (*TestUserVerifier) SignAdminInMethod(clientId string, w http.ResponseWriter, r *http.Request) (bool, error) {
	return true, nil
}

func (*TestUserVerifier) SignInMethodK(http.Handler, *keytab.Keytab, *ll.Logger, string, *BearerServer) http.Handler {
	return nil
}

func TestGenerateTokensByUsername(t *testing.T) {
	r := new(http.Request)
	token, refresh, err := _sut.generateTokens(UserToken, "user111", "", r)
	if err == nil {
		t.Logf("Token: %v", token)
		t.Logf("Refresh Token: %v", refresh)
	} else {
		t.Fatalf("Error %s", err.Error())
	}
}
