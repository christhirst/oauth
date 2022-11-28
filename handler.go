package oauth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	gohelper "github.com/christhirst/gohelper/ihttp"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

var refresh_token, redirect_uri, Secret string
var at AuthToken

func (bs *BearerServer) Registration(w http.ResponseWriter, r *http.Request) {
	/* authH := r.Header.Get("Authorization")
	//groups, err := bs.verifier.ExtractJWTtoUserGroup(authH)
	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	} */
	//iamAdmin := slices.Contains(groups, "group1")
	//ww, _ := bs.verifier.SignAdminInMethod("", w, r)

	iamAdmin := true
	if iamAdmin {
		switch r.Method {
		case "GET":
			var clientConfig interface{}
			path := r.URL.Path
			base := strings.LastIndex(path, "/")
			clientID := path[base+1:]
			if path[:base+1] == "/oauth/" && clientID == "clients" {
				clients, err := bs.verifier.StoreClientsGet()
				if err != nil {
					log.Error().Err(err).Msg("Unable to get clients")
				}
				renderJSON(w, clients, 200)
			} else if path[:base+1] == "/oauth/clients/" {
				client, err := bs.verifier.StoreClientGet(clientID)
				if err != nil {
					log.Error().Err(err).Msgf("Unable to get client %s", client)
				}
				renderJSON(w, client, 200)
			}
			renderJSON(w, clientConfig, 401)
		case "POST", "PUT":
			jsonMap := &Registration{}
			_, err := gohelper.ParseBody(r, jsonMap)
			if err != nil {
				log.Err(err)
				renderJSON(w, "Failed parsing client config", 422)
			}
			regResp, err := bs.verifier.StoreClient(jsonMap.Client_name, *jsonMap, r.Method)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
				renderJSON(w, "Failed parsing client config", 422)
			}
			renderJSON(w, regResp, 200)
		case "DELETE":
			jsonMap := Registration{}
			_, err := gohelper.ParseBody(r, jsonMap)
			if err != nil {
				log.Err(err)
			}
			err = bs.verifier.StoreClientDelete([]string{jsonMap.Client_name})
			if err != nil {
				renderJSON(w, jsonMap, 500)
			}
			renderJSON(w, jsonMap, 200)
		default:
			log.Error().Msg("failed")
		}
	}
}

func (bs *BearerServer) ConnectionTargetEp(w http.ResponseWriter, r *http.Request) {
	if true {
		switch r.Method {
		case "GET":
			var clientConfig interface{}
			var err error
			clientConfig, err = bs.verifier.StoreKeysGet()
			rc := 200
			if err != nil {
				log.Err(err)
				rc = 500
			}
			renderJSON(w, clientConfig, rc)
		case "POST":
			var keys map[string]string
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			err = json.Unmarshal(body, &keys)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
			//err = bs.verifier.
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		case "DELETE":
			//path := r.URL.Path
			/* base := strings.LastIndex(path, "/")
			clientID := path[base+1:]  */
			kid := chi.URLParam(r, "kid")
			//keyDeleteKeyPair(bs.Kc, kid)
			err := bs.verifier.StoreKeyDelete([]string{kid})
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		}
	}
}

func (bs *BearerServer) KeyEndpoint(w http.ResponseWriter, r *http.Request) {
	/* authH := r.Header.Get("Authorization")
	groups, err := bs.verifier.ExtractJWTtoUserGroup(authH)
	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	}
	iamAdmin := slices.Contains(groups, "group1") */
	if true {
		switch r.Method {
		case "GET":
			var clientConfig interface{}
			var err error
			clientConfig, err = bs.verifier.StoreKeysGet()
			rc := 200
			if err != nil {
				log.Err(err)
				rc = 500
			}
			renderJSON(w, clientConfig, rc)
		case "POST":
			var keys map[string]string
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
			}
			err = json.Unmarshal(body, &keys)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
			err = bs.verifier.StoreKey(keys)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		case "DELETE":
			//path := r.URL.Path
			/* base := strings.LastIndex(path, "/")
			clientID := path[base+1:]  */
			kid := chi.URLParam(r, "kid")
			//keyDeleteKeyPair(bs.Kc, kid)
			err := bs.verifier.StoreKeyDelete([]string{kid})
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		}
	}
}

func (bs *BearerServer) GetRedirect(w http.ResponseWriter, r *http.Request) {
	formList := []string{"name", "password", "client_id", "response_type", "redirect_uri", "scope", "nonce", "state"}
	formMap, _, err := formExtractor(r, formList)
	if err != nil {
		log.Error().Err(err).Msg("Form Value not present")
	}

	userStoreName, _, err := bs.verifier.GetConnectionTarget(r)
	if err != nil {
		log.Error().Err(err).Msg("Failed getting conncetion target")
	}

	_, err = bs.verifier.SessionSave(w, r, formMap["name"][0], "user_session")
	if err != nil {
		log.Error().Err(err).Msg("Failed saving session")
	}

	groups, err := bs.verifier.ValidateUser(formMap["name"][0], formMap["password"][0], formMap["scope"][0], userStoreName, r)
	if err != nil {
		log.Error().Err(err).Msg("Failed validating user getting groups")
	}

	var authParameter = AuthToken{
		Iss:   formMap["client_id"][0],
		Sub:   formMap["client_id"][0],
		Aud:   formMap["client_id"],
		Nonce: formMap["nonce"][0],
		//exp:       exp,
		//iat:       iat,
		//auth_time: auth_time,
		//acr:       acr,
		//azp:       azp,
	}

	claims := bs.verifier.CreateClaims(formMap["name"][0], formMap["client_id"], formMap["nonce"][0], groups, authParameter, r)
	access_token, err := CreateJWT("RS256", claims, bs.Kc)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create access_token")
	}
	id_token, err := CreateJWT("RS256", claims, bs.Kc)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create id_token")
	}
	OpenIDConnectFlows(id_token, access_token, formMap["response_type"][0], formMap["redirect_uri"][0], formMap["state"][0], formMap["scope"], w, r)
}

type JWT struct {
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

func (bs *BearerServer) UserInfo(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("Unable to create id_token")
	}
	headerEntry := strings.Split(r.Header.Get("Authorization"), " ")
	if len(headerEntry) < 2 {
		renderJSON(w, nil, http.StatusForbidden)
	}
	jwtToken := headerEntry[1]
	jwtSplit := strings.Split(jwtToken, ".")
	jwtHeader, _ := base64.RawStdEncoding.DecodeString(jwtSplit[0])

	jwtParsed := JWT{}
	err = json.Unmarshal(jwtHeader, &jwtParsed)
	if err != nil {
		fmt.Println("error:", err)
	}
	_, ok := bs.Kc.Pk[jwtParsed.Kid]

	var pk *rsa.PublicKey
	if !ok {
		log.Error().Err(err).Msgf("Key not available: %s", jwtParsed.Kid)
	} else {
		pk = &bs.Kc.Pk[jwtParsed.Kid].PublicKey
	}

	if ok {
		parsedToken, err := JWTvalid(jwtToken, pk)
		if err != nil {
			fmt.Println("error:", err)
		}
		ee := parsedToken.Claims.(jwt.MapClaims)
		username := ee["sub"].(string)

		//get userdata
		groups, err := bs.verifier.ValidateUser(username, "password", "scope", "userStoreName", r)
		if err != nil {
			log.Error().Err(err).Msg("Parsing Form failed")
		}
		fmt.Println(groups)
		jsonPayload, rc, contentType, err := UserData()
		if err != nil {
			log.Error().Err(err).Msg("Unable to create id_token")
		}
		w.Header().Set("Content-Type", contentType)
		renderJSON(w, jsonPayload, rc)
		return
	}

	renderJSON(w, nil, http.StatusForbidden)
}
func (bs *BearerServer) GetConnectionTarget(r *http.Request) (string, *AuthTarget, error) {
	return "false", &AuthTarget{}, nil
}
