package oauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

func (bs *BearerServer) SignIn(w http.ResponseWriter, r *http.Request) {
	//getting the session
	fmt.Println("SignIn")
	userID, ok, err := bs.Verifier.SessionGet(w, r, "user_session")
	if err != nil {
		log.Error().Err(err).Msgf("No session present for: %s", userID)
	}
	//getting the form fields
	//TODO nonce optional
	formList := []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce"}
	queryListMap, err := UrlExtractor(r, formList)
	fmt.Println(queryListMap)

	getFormData([]string{}, r)
	if err != nil {
		log.Error().Err(err).Msg("Form value not present")
		renderJSON(w, "Form value is missing", http.StatusForbidden)
		return
	}
	//getting the client data
	aud := queryListMap["client_id"][0]
	client, err := bs.Verifier.StoreClientGet(aud)
	if err != nil {
		log.Error().Err(err).Msg("Failed getting client data")
		renderJSON(w, "Client not found", http.StatusForbidden)
		return
	}

	//redirect to error page || Logged in || to login page
	if err != nil && client == nil {
		log.Info().Msgf("Client not found: %s", aud)
		http.Redirect(w, r, "https://ClientNotFound", 401)
	} else if ok && userID != "" {
		fmt.Println(client)
		RedirectAccess(bs, w, r)
	} else {
		err := bs.Verifier.SignInMethod(aud, w, r)

		if err != nil {
			log.Error().Err(err).Msgf("No session present for: %s", userID)
		}
		//getting the form fields
		//TODO nonce optional
		formList := []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce"}
		queryListMap, err := UrlExtractor(r, formList)

		getFormData([]string{}, r)
		if err != nil {
			renderJSON(w, "Form value is missing", http.StatusForbidden)
			return
		}

		//getting the client data
		aud := queryListMap["client_id"][0]
		client, err := bs.Verifier.StoreClientGet(aud)
		if err != nil {
			log.Error().Err(err).Msg("Failed getting client data")
			renderJSON(w, "Client not found", http.StatusForbidden)
			return
		}

		//redirect to error page || Logged in || to login page
		if err != nil && client == nil {
			log.Info().Msgf("Client not found: %s", aud)
			http.Redirect(w, r, "https://ClientNotFound", 401)
		} else if ok && userID != "" {
			fmt.Println(client)
			RedirectAccess(bs, w, r)
		} else {
			err := bs.Verifier.SignInMethod(aud, w, r)
			if err != nil {
				log.Error().Err(err).Msg("Signin method failed")
			}
		}
	}
}

type FormList struct {
	ClientID     string
	ResponseType string
	RedirectURI  []string
	Scope        []string
	Nonce        string
	State        string
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
		Nonce:        urlValues["nonce"][0],
		State:        urlValues["state"][0],
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

	fmt.Println(r.Host)
	fmt.Println("iss")
	clientId := urlValues["client_id"]
	nonce := "code"
	if _, ok := urlValues["nonce"]; ok {
		nonce = urlValues["nonce"][0]
	}
	fmt.Println(nonce)

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
