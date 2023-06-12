package oauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

func (bs *BearerServer) SignIn(w http.ResponseWriter, r *http.Request) {
	userID, ok, err := bs.Verifier.SessionGet(w, r, "user_session")
	if err != nil {
		log.Error().Err(err).Msgf("No session present for: %s", userID)
	}
	aud := r.FormValue("client_id")
	client, err := getClient(bs, w, r, aud)
	if err != nil || client == nil {
		log.Error().Err(err).Msg("Failed getting client data")
		renderJSON(w, fmt.Sprintf("Failed getting client data: %v", err), http.StatusForbidden)
		return
	}

	if ok && userID != "" {
		RedirectAccess(bs, w, r)
	} else {
		err := handleSignInMethod(bs, w, r, aud, userID)
		if err != nil {
			log.Error().Err(err).Msg("Signin method failed")
		}
	}
}

func RedirectAccess(bs *BearerServer, w http.ResponseWriter, r *http.Request) {
	formList := []string{"state", "client_id", "response_type", "redirect_uri", "scope", "nonce"}
	urlValues, err := UrlExtractor(r, formList)
	if err != nil {
		log.Error().Err(err).Msg("Form value not present")
		renderJSON(w, "Form value is missing", http.StatusForbidden)
		return
	}

	formData := FormList{
		ClientID:     urlValues["client_id"][0],
		ResponseType: urlValues["response_type"][0],
		RedirectURI:  urlValues["redirect_uri"],
		Scope:        urlValues["scope"],
	}

	nonce := ""
	if _, ok := urlValues["nonce"]; ok {
		formData.Nonce = urlValues["nonce"][0]
		nonce = urlValues["nonce"][0]
	}

	if _, ok := urlValues["nonce"]; ok {
		formData.State = urlValues["state"][0]
	}

	if client, err := bs.Verifier.StoreClientGet(urlValues["client_id"][0]); err != nil {
		log.Error().Err(err).Msgf("Failed getting Client: %s", client)
	}
	fmt.Println("RedirectAccess")
	userID, _, err := bs.Verifier.SessionGet(w, r, "user_session")
	if err != nil {
		userID = r.Form.Get("name")
		log.Err(err).Msgf("Unable to get session for User: %s", userID)
	}

	clientId := urlValues["client_id"]

	_, groups, err := bs.Verifier.UserLookup(userID, urlValues["scope"])
	if err != nil {
		log.Err(err).Str("Userlookup", "failed").Msgf("Failed getting Groups from userstore, Group length: %d", len(groups))
	}

	claims := bs.Verifier.CreateClaims(userID, formData, groups, r)
	access_token, _ := CreateJWT("RS256", claims, bs.Kc)
	id_token, _ := CreateJWT("RS256", claims, bs.Kc)

	code, _ := generateRandomString(22)

	codeCheck := CodeCheck{
		Code:     code,
		User:     userID,
		Nonce:    nonce,
		ClientId: clientId[0],
	}
	fmt.Println(code, codeCheck)
	bs.Tm.Set(code, codeCheck, 3*time.Second)

	OpenIDConnectFlows(code, id_token, access_token, formData, w, r)
}

func handleClientNotFound(bs *BearerServer, w http.ResponseWriter, r *http.Request, aud string) {
	log.Info().Msgf("Client not found: %s", aud)
	http.Redirect(w, r, "https://ClientNotFound", http.StatusUnauthorized)
}

func handleSignInMethod(bs *BearerServer, w http.ResponseWriter, r *http.Request, aud string, userID string) error {
	err := bs.Verifier.SignInMethod(aud, w, r)
	if err != nil {
		log.Error().Err(err).Msgf("No session present for: %s", userID)
	}
	return err
}

func getClient(bs *BearerServer, w http.ResponseWriter, r *http.Request, aud string) (*Registration, error) {
	client, err := bs.Verifier.StoreClientGet(aud)
	if err != nil {
		log.Error().Err(err).Msg("Failed getting client data")
		return nil, err
	}

	if client == nil {
		handleClientNotFound(bs, w, r, aud)
		return nil, nil
	}

	return client, nil
}
