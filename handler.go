package oauth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/christhirst/gohelper/ihttp"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
)

var refresh_token, redirect_uri string
var at AuthToken

func (bs *BearerServer) Registration(w http.ResponseWriter, r *http.Request) {
	/* authH := r.Header.Get("Authorization")
	//groups, err := bs.Verifier.ExtractJWTtoUserGroup(authH)
	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	} */
	//iamAdmin := slices.Contains(groups, "group1")
	//ww, _ := bs.Verifier.SignAdminInMethod("", w, r)

	iamAdmin := true
	if iamAdmin {
		switch r.Method {
		case "GET":
			path := r.URL.Path
			base := strings.LastIndex(path, "/")
			clientID := path[base+1:]
			if path[:base+1] == "/oauth/" && clientID == "clients" {
				clients, err := bs.Verifier.StoreClientsGet()
				clientsList := []Registration{}
				for _, v := range clients {
					clientsList = append(clientsList, *v)
				}

				if err != nil {
					log.Error().Err(err).Msg("Unable to get clients")
				}
				renderJSON(w, clientsList, 200)
			} else if path[:base+1] == "/oauth/clients/" {
				client, err := bs.Verifier.StoreClientGet(clientID)
				if err != nil {
					log.Error().Err(err).Msgf("Unable to get client %s", client)
				}
				renderJSON(w, client, 200)
			} else {
				var clientConfig interface{}
				renderJSON(w, clientConfig, 401)
			}

		case "POST", "PUT":
			jsonMap := &Registration{}
			_, err := ihttp.ParseBody(r, jsonMap)
			if err != nil {
				log.Err(err)
				renderJSON(w, "Failed parsing client config", 422)
			}
			regResp, err := bs.Verifier.StoreClient(jsonMap.Client_name, *jsonMap, r.Method)
			if err != nil {
				log.Error().Err(err).Msg("Unable to read body")
				renderJSON(w, "Failed parsing client config", 422)
			}
			renderJSON(w, regResp, 200)
		case "DELETE":
			clientId := path.Base(r.URL.Path)

			err := bs.Verifier.StoreClientDelete([]string{clientId})
			if err != nil {
				renderJSON(w, "failed", 500)
			}
			renderJSON(w, "deleted: "+clientId, 200)
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
			clientConfig, err = bs.Verifier.StoreKeysGet()
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
			//err = bs.Verifier.
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		case "DELETE":
			//path := r.URL.Path
			/* base := strings.LastIndex(path, "/")
			clientID := path[base+1:]  */
			kid := chi.URLParam(r, "kid")
			//keyDeleteKeyPair(bs.Kc, kid)
			err := bs.Verifier.StoreKeyDelete([]string{kid})
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		}
	}
}

func (bs *BearerServer) KeyEndpoint(w http.ResponseWriter, r *http.Request) {
	/* authH := r.Header.Get("Authorization")
	groups, err := bs.Verifier.ExtractJWTtoUserGroup(authH)
	if err != nil {
		log.Error().Err(err).Msg("Unable to ExtractUser from JWT")
	}
	iamAdmin := slices.Contains(groups, "group1") */

	if true {
		switch r.Method {
		case "GET":
			fmt.Println("uuu")
			var clientConfig interface{}
			var err error
			clientConfig, err = bs.Verifier.StoreKeysGet()
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
			err = bs.Verifier.StoreKey(keys)
			if err != nil {
				log.Error().Err(err).Msg("Unable to Unmarshal file")
			}
		case "DELETE":

			//path := r.URL.Path
			/* base := strings.LastIndex(path, "/")
			clientID := path[base+1:]  */
			kid := chi.URLParam(r, "kid")
			fmt.Println(path.Base(r.URL.Path))
			//keyDeleteKeyPair(bs.Kc, kid)
			err := bs.Verifier.StoreKeyDelete([]string{kid})
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

	formData := &FormList{}
	err = FillStruct(formData, formMap)
	if err != nil {
		log.Err(err).Msg("Failed to fill struct")
	}

	nonce := formData.Nonce

	_, err = bs.Verifier.SessionSave(w, r, formMap["name"][0], "user_session")
	if err != nil {
		log.Error().Err(err).Msg("Failed saving session")
	}

	groups, err := bs.Verifier.ValidateUser(formMap["name"][0], formMap["password"][0], "", r)
	if err != nil {
		log.Error().Err(err).Msg("Failed validating user getting groups")
	}
	/*
		var authParameter = AuthToken{
			Iss:   formMap["client_id"][0],
			Sub:   formMap["client_id"][0],
			Aud:   formMap["client_id"],
			Nonce: nonce,
			//exp:       exp,
			//iat:       iat,
			//auth_time: auth_time,
			//acr:       acr,
			//azp:       azp,
		} */

	claims := bs.Verifier.CreateClaims(formMap["name"][0], *formData, groups, r)
	access_token, err := CreateJWT("RS256", claims, bs.Kc)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create access_token")
	}
	id_token, err := CreateJWT("RS256", claims, bs.Kc)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create id_token")
	}

	code, _ := generateRandomString(22)

	codeCheck := CodeCheck{
		Code:     code,
		User:     formMap["name"][0],
		ClientId: formMap["client_id"][0],
		Nonce:    nonce,
	}
	bs.Tm.Set(code, codeCheck, 3*time.Second)

	OpenIDConnectFlows(code, id_token, access_token, *formData, w, r)
}

type JWT struct {
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

func GetJwtHeader(jwtToken string) (JWT, error) {
	jwtParsed := JWT{}
	jwtSplit := strings.Split(jwtToken, ".")
	jwtHeader, _ := base64.RawStdEncoding.DecodeString(jwtSplit[0])
	err := json.Unmarshal(jwtHeader, &jwtParsed)
	if err != nil {
		return jwtParsed, err
	}
	return jwtParsed, nil
}

func getHeader(header string, w http.ResponseWriter, r *http.Request) (jwt string, err error) {
	authToken := r.Header.Get(header)
	headerEntry := strings.Split(authToken, " ")
	if len(headerEntry) < 2 || authToken == "" {
		log.Error().Err(nil).Msg("No Authorization header")
		renderJSON(w, nil, http.StatusForbidden)
		jwt = ""
		err = errors.New("No authorization header")
		return
	}
	jwt = headerEntry[1]
	err = nil
	return
}

func (bs *BearerServer) UserInfo(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Error().Err(err).Msg("Unable to parse form")
		return
	}
	jwtToken, err := getHeader("Authorization", w, r)
	if err != nil {
		log.Error().Err(err).Msg("Unable to get jwt-authtoken")
		return
	}
	jwtHeader, err := GetJwtHeader(jwtToken)
	if err != nil {
		log.Error().Err(err).Msg("Unable to get jwt-header")
		return
	}

	var pk *rsa.PublicKey
	_, ok := bs.Kc.Pk["test"]
	if !ok {
		log.Error().Err(err).Msgf("Key not available: %s", jwtHeader.Kid)
	} else {
		//bs.Kc.Pk[jwtParsed.Kid]
		pk = &bs.Kc.Pk["test"].PublicKey
	}

	if ok {
		jwtParsed, err := ParseJWT(jwtToken, pk)
		if err != nil {
			log.Error().Err(err).Msgf("JWT validation failed for kid: %s", jwtHeader.Kid)
		}
		// BUG  panic: interface conversion: interface {} is nil, not string
		// 9:45PM ERR JWT validation failed for kid: 051c42ab-a832-4f94-81a4-45feefa73fec error="Token invalid"
		username := jwtParsed["sub"].(string)

		allUserInfos, err := bs.Verifier.GetUserData(username, "scope", r)
		/* groups, err := bs.Verifier.ValidateUser(username, "password", "scope", r)
		if err != nil {
			log.Error().Err(err).Msg("Parsing Form failed")
		} */
		/* groups, err = bs.Verifier.ExtractJWTtoUserGroup("")
		//.Allcon.AllConns[authTarget].Conns[ldapCon].LdapGetMemberOf(baseDN, sizeLimit, filterLDAP)
		if err != nil {
			log.Error().Err(err).Msgf("Failed getting groups for: %s", username)
			fmt.Println("eee")
		} */
		//fmt.Println(groups)
		jsonPayload, rc, contentType, err := UserData(allUserInfos)
		if err != nil {
			log.Error().Err(err).Msg("Unable to create id_token")
		}
		w.Header().Set("Content-Type", contentType)
		renderJSON(w, jsonPayload, rc)
		return
	}
	fmt.Println("ssws")
	renderJSON(w, nil, http.StatusForbidden)
}
func (bs *BearerServer) GetConnectionTarget(r *http.Request) (string, *AuthTarget, error) {
	return "false", &AuthTarget{}, nil
}
