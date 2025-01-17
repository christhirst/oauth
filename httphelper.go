package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

func formAddList(uv *url.Values, uvm map[string][]string) {
	for i, v := range uvm {
		for _, vv := range v {
			uv.Add(i, vv)
		}
	}
}

func qAddList(r *http.Request, uvm map[string][]string) {
	q := r.URL.Query()
	for i, v := range uvm {
		for _, vv := range v {
			q.Add(i, vv)

		}
	}
	r.URL.RawQuery = q.Encode()
}

func formExtractor(r *http.Request, formList []string) (formMap map[string][]string, notPresent []string, err error) {
	err = r.ParseForm()
	if err != nil {
		log.Err(err).Msg("Parsing form failed")
	}
	notPresent = []string{}
	formMap = map[string][]string{}
	for _, v := range formList {
		if x := r.Form[v]; len(r.Form[v]) > 0 {
			formMap[v] = x
		} else {
			notPresent = append(notPresent, v)
		}
	}
	return

}
func UrlExtractor(r *http.Request, formList []string) (queryListMap map[string][]string, err error) {
	queryListMap = make(map[string][]string)
	for i, v := range r.URL.Query() {
		fmt.Println(i, v)
		if len(v) > 0 {
			queryListMap[i] = v
		}
	}
	if len(formList) <= len(queryListMap) {
		err = nil
		return
	} else {
		var notPresent string
		for _, v := range formList {
			if len(r.URL.Query()[v]) == 0 {
				notPresent = v
			}
			err = errors.New("One postForm Value not present: " + notPresent)
		}
		return
	}

}
func getFormData(formValues []string, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		log.Err(err)
	}
	for key, values := range r.Form { // range over map
		for _, value := range values { // range over []string
			fmt.Println(key, value)
		}
	}

}

func Unauthorized(bs *BearerServer, client_id string) (bool, error) {
	client, err := bs.Verifier.StoreClientGet(client_id)
	if client != nil {
		return false, err
	}
	return true, err

}

func Forbidden(scope jwt.Claims) (bool, error) {
	return false, nil
}

func OpenIDConnectFlows(code, id_token, access_token string, formData FormList, w http.ResponseWriter, r *http.Request) {
	switch formData.ResponseType {
	case "id_token":
		fmt.Println(111)
		location := formData.RedirectURI[0] + "?id_token=" + id_token + "&state=" + formData.State
		w.Header().Add("Location", location)
		http.Redirect(w, r, location, 302)
	case "code":
		fmt.Println(222)
		//TODO needs fixxing code= not ID token
		//if slices.Contains(scope, "openid") {

		//location := redirect_uri + "?code=" + access_token + "&state=" + state
		location := formData.RedirectURI[0] + "?code=" + code + "&state=" + formData.State
		w.Header().Add("Location", location)
		http.Redirect(w, r, location, 302)
		//}
	case "id_token token": //insecure
		location := formData.RedirectURI[0] + "&access_token=" + access_token + "&token_type=" + "token_type" + "&id_token=" + id_token + "&state=" + formData.State
		w.Header().Add("Location", location)
	case "code id_token":
		fmt.Println(333)
		if slices.Contains(formData.Scope, "openid") {
			location := formData.RedirectURI[0] + "?code=" + access_token + "&state=" + formData.State
			w.Header().Add("Location", location)
			http.Redirect(w, r, location, 302)
		}
	case "code token": //insecure
		location := formData.RedirectURI[0] + "&code=" + access_token + "&access_token=" + access_token + "&token_type=" + "token_type" + "&state=" + formData.State
		w.Header().Add("Location", location)
		//"code id_token token"
	case "code token id_token": //insecure

		location := formData.RedirectURI[0] + "&code=" + access_token + "&access_token=" + access_token + "&token_type=" + "token_type" + "&id_token=" + id_token + "&state=" + formData.State
		w.Header().Add("Location", location)
		http.Redirect(w, r, location, 302)
	default:
		log.Error().Err(errors.New("invalid response type")).Msg("response_type not present")
	}
	//todo: OAuth client credentials flow; OAuth device flow

}
