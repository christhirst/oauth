package oauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

const idTokenSigningAlg = "RS256"

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	formList := []string{"authorization_code", "code", "redirect_uri"}
	formMap, _, err := formExtractor(r, formList)
	if err != nil {
		log.Error().Err(err).Msg("Form Value not present")
	}
	authheader := r.Header.Get("Authorization")
	fmt.Println(authheader)
	idToken := strings.Split(authheader, " ")[1]
	fmt.Println(idToken)
	dIdToken, _ := base64.RawStdEncoding.DecodeString(idToken)
	eee := strings.Split(string(dIdToken), " ")
	fmt.Println(eee)

	bs.Verifier.ValidateClient(eee[0], eee[1])

	code := formMap["code"][0]
	redirect_uri := formMap["redirect_uri"]

	grant_type := GrantType(r.FormValue("grant_type"))

	codeCheck, ok := bs.Tm.GetValue(code).(CodeCheck)
	if !ok {
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}
	fmt.Println(codeCheck)

	iss := r.Host
	//TODO redirect is slice Base: Decoden equal check with memory and then pass
	resp, returncode, err := bs.GenerateIdTokenResponse(
		codeCheck,
		idTokenSigningAlg,
		iss,
		[]string{codeCheck.ClientId},
		grant_type,
		refresh_token,
		codeCheck.ClientId,
		redirect_uri[0],
		at,
		w,
		r,
	)

	if err != nil || returncode != 200 {
		renderJSON(w, err, returncode)
		return
	}
	renderJSON(w, resp, http.StatusOK)
}

// UserCredentials manages password grant type requests
func (bs *BearerServer) TokenIntrospect(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Err(err)
	}
	token := r.PostForm["token"]
	parsedToken, err := JWTvalid(token[0], &bs.Kc.Pk["test"].PublicKey)
	if err != nil {
		log.Err(err).Msg("Token is invalid")
		renderJSON(w, nil, 401)
		return
	}

	//getting scope
	scopes, err := parseScopes(parsedToken)
	if err != nil {
		log.Err(err).Msg("Parsing scopes failed")
	}
	client_id, err := parseClientid(parsedToken)
	if err != nil {
		log.Err(err).Msg("Parsing client_id failed")
	}
	if client_id == "" {
		log.Err(err).Msg("No Client_id")
		renderJSON(w, nil, 401)
		return
	}

	if unauthorized, _ := Unauthorized(bs, client_id); unauthorized {
		log.Err(err).Msg("Wrong client_id, unauthorized")
		renderJSON(w, nil, 401)
		return
	}

	if unallowed, _ := Forbidden(parsedToken.Claims); unallowed {
		log.Err(err).Msg("Wrong claims, unallowed")
		renderJSON(w, nil, 401)
		return
	}

	if err == nil && len(token) > 0 && parsedToken.Valid {
		qq := IntroSpectReturn{Active: "true", Scope: scopes, Client_id: client_id, Username: "", Token_type: ""}
		renderJSON(w, qq, 200)
		return
	} else if !false {
	} else {
		renderJSON(w, nil, 400)
		return
	}
	//401 Unauthorized
	//403 Forbidden

}
func (bs *BearerServer) TokenRevocation(w http.ResponseWriter, r *http.Request) {
	/* 	400 Bad Request
	Invalid or malformed request.
			   	401 Unauthorized
			   	500 Internal Server Error
				 application/x-www-form-urlencoded
				[ Issuer ]
				Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

				Body
				access_token -- the token is an access token

		refresh_token -- the token is a refresh token
		token=Ohw8choo.wii3ohCh.Eesh1AeDGong3eir
	&token_type_hint=refresh_token
	token=Ohw8choo.wii3ohCh.Eesh1AeDGong3eir
	*/
	if true {
		switch r.Method {
		case "GET":
		default:
			log.Error().Msg("failed")
		}
	}
	renderJSON(w, nil, 200)
}
