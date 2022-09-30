package oauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

func (bs *BearerServer) OpenidConfig(w http.ResponseWriter, r *http.Request) {
	baseURL := scheme + r.Host
	j := OpenidConfig{
		Issuer:                                baseURL,
		Authorization_endpoint:                baseURL + "/oauth/authorize",
		Token_endpoint:                        baseURL + "/oauth/token",
		Introspection_endpoint:                baseURL + "/oauth/introspect",
		Userinfo_endpoint:                     baseURL + "/oauth/userinfo",
		Registration_endpoint:                 baseURL + "/oauth/clients",
		Jwks_uri:                              baseURL + "/oauth/keys",
		Revocation_endpoint:                   baseURL + "/oauth/revoke",
		Scopes_supported:                      []string{"api", "read_api", "read_user", "read_repository", "write_repository", "read_registry", "write_registry", "sudo", "openid", "profile", "email"},
		Response_types_supported:              []string{"code"},
		Response_modes_supported:              []string{"query", "fragment"},
		Grant_types_supported:                 []string{"authorization_code", "password", "client_credentials", "refresh_token"},
		Token_endpoint_auth_methods_supported: []string{"client_secret_basic", "client_secret_post"},
		Subject_types_supported:               []string{"public"},
		Id_token_signing_alg_values_supported: []string{"RS256"},
		Claims_supported:                      []string{"iss", "sub", "aud", "exp", "iat", "sub_legacy", "name", "nickname", "email", "email_verified", "website", "profile", "picture", "groups", "groups_direct"},
	}
	renderJSON(w, j, 200)
}

func RedirectAccess(bs *BearerServer, w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query()["state"][0]
	userID, _, err := bs.verifier.SessionGet(w, r, "user_session")
	//if len(r.URL.Query()["client_id"]) > 0 {
	aud := r.URL.Query()["client_id"][0]
	bs.nonce = r.URL.Query()["nonce"][0]
	response_type := r.URL.Query()["response_type"][0]
	scopes := strings.Split(r.URL.Query()["scope"][0], ",")
	nonce := r.URL.Query()["nonce"][0]
	redirect_uri := r.URL.Query()["redirect_uri"][0]
	state = r.URL.Query()["state"][0]
	fmt.Println(aud)
	fmt.Println(nonce)
	fmt.Println(redirect_uri)
	fmt.Println(state)
	fmt.Println(response_type)
	fmt.Println(scopes)
	//}
	fmt.Println(userID)
	//access_token, err := JWTCreateAccessT(bs, r)
	if err != nil {
		log.Err(err)
	}
	var authParameter = AuthToken{
		Iss:       "iss",
		Sub:       "sub",
		Aud:       aud,
		Exp:       jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		Iat:       "",
		Jti:       "",
		Client_id: "Testclient_id",
		Scope:     []string{"scope1", "scope2"},
		Nonce:     nonce,
	}
	_, groups, err := bs.verifier.UserLookup(userID, scopes)

	//claims := CreateClaims(authParameter, bs.nonce, groups, r)
	claims := bs.verifier.CreateClaims(userID, aud, nonce, groups, authParameter, r)
	access_token, _ := CreateJWT("RS256", claims, bs.Kc)
	//location := redirect_uri + "?code=" + access_token + "&state=" + state
	//w.Header().Add("Location", location)
	//http.Redirect(w, r, location, 302)

	id_token, _ := CreateJWT("RS256", claims, bs.Kc)
	OpenIDConnectFlows(id_token, access_token, response_type, redirect_uri, state, scopes, w, r)
}

/* func GetSession(bs *BearerServer, w http.ResponseWriter, r *http.Request) (bool, error) {
	store, err := session.Start(context.Background(), w, r)
	_, ok := store.Get("foo")
	fmt.Println(ok)
	return ok, err

} */

func (bs *BearerServer) SignIn(w http.ResponseWriter, r *http.Request) {
	userID, ok, err := bs.verifier.SessionGet(w, r, "user_session")
	if err != nil {
		log.Error().Err(err).Msg(userID)
	}
	aud := r.URL.Query()["client_id"][0]
	client, err := bs.verifier.StoreClientGet(aud)
	if client == nil {
		http.Redirect(w, r, "http://error", 401)
	}

	fmt.Println(userID)
	fmt.Println("oooo")
	if err != nil {
		log.Error().Err(err).Msg(userID)
	}
	if ok {
		RedirectAccess(bs, w, r)
	} else {
		fmt.Fprintf(w, `<h1>Login</h1>
    <form method="post" action="/oauth/auth?%s">
        <label for="name">User name</label>
        <input type="text" id="name" name="name">
        <label for="password">Password</label>
        <input type="password" id="password" name="password">
        <button type="submit">Login</button>
    </form>  `, r.URL.RawQuery)
	}
}
