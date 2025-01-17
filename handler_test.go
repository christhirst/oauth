package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/christhirst/gohelper/iasserts"
	"github.com/christhirst/gohelper/ijson"
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
)

var pk, _ = rsa.GenerateKey(rand.Reader, 4096)
var bs = NewBearerServer(
	"mySecretKey-10101",
	time.Second*120,
	&TestUserVerifier{},
	nil,
)
var testclaims = MyCustomClaimss{
	Nonce:  "nonce",
	Groups: []string{"testgroup1", "testgroup2"},
	RegisteredClaims: jwt.RegisteredClaims{
		// A usual scenario is to set the expiration time relative to the current time
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "baseURL" + "",
		Subject:   "testSubject",
		ID:        "1",
		Audience:  []string{"rrr"},
	},
}

var clientConfig = ClientConfig{Method: "RS256", Claims: testclaims, Kid: sig.String()}
var signedToken, _ = CreateJWT(clientConfig.Method, clientConfig.Claims, bs.Kc)
var theTests = []struct {
	name               string
	url                string
	method             string
	params             []postData
	expectedStatusCode int
	Host               string
	Authorization      string
}{
	{
		"config1", "/oauth/clients", "POST",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
	{
		"config2", "/oauth/clients/testclient1", "GET",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
	{
		"config3", "/oauth/clients", "GET",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
	{
		"config4", "/oauth/clients/testclient1", "DELETE",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
	{
		"config5", "/oauth/clients/testclient1", "GET",
		[]postData{}, http.StatusOK, "localhost",
		"Bearer " + signedToken,
	},
}

var client = Registration{
	Client_id:      "testclient1",
	Client_secret:  "test_secret",
	Redirect_uris:  []string{"http://test.de"},
	Response_types: "POST",
}

var sig, _ = uuid.FromBytes(pk.PublicKey.N.Bytes())

func assertResponseBody[k comparable](t testing.TB, got, want k) {
	t.Helper()
	if got != want {
		t.Errorf("expected %v but got %v", got, want)
	}
}

/*
	 func executeRequest(req *http.Request, mux *chi.Mux) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
*/
func createRequest[K any](c K, t *testing.T) bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(c)
	if err != nil {
		t.Errorf("json encoding failed %v", err)
	}
	return buf
}

func TestKeyEndpointPost(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, get map[string]string, want map[string]string) {

		empJSON, err := json.Marshal(get)
		if err != nil {
			log.Fatalf(err.Error())
		}
		//pass request to handler with nil as parameter
		req, err := http.NewRequest("POST", "/oauth/keys", bytes.NewBuffer(empJSON))
		req.Header.Set("Content-Type", "application/json")
		if err != nil {
			t.Fatal(err)
		}
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		httpRecorder := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.KeyEndpoint)

		//call ServeHTTP method and pass  Request and ResponseRecorder.
		handler.ServeHTTP(httpRecorder, req)
		bodybytes := httpRecorder.Body
		jmap, err := ijson.StructToJson(bodybytes)
		//bodyBytes, err := io.ReadAll(rr.Body)
		if err != nil {
			log.Fatal(err)
		}

		jsonStr, err := json.Marshal(jmap)
		if err != nil {
			log.Fatal(err)
		}

		// convert json to struct
		var keys map[string]string
		err = json.Unmarshal(jsonStr, &keys)
		if err != nil {
			log.Fatal(err)
		}
	}

	t.Run("Registration Test 1", func(t *testing.T) {
		got := map[string]string{"s": `-----BEGIN RSA PRIVATE KEY-----
		MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
		KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
		o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
		TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
		9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
		v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
		/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
		-----END RSA PRIVATE KEY-----`}

		assertCorrectMessage(t, got, got)
	})
}

func TestKeyEndpointGet(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, get, want string) {

	}

	t.Run("Registration Test 1", func(t *testing.T) {
		got := ""

		assertCorrectMessage(t, got, got)
	})
}

func TestKeyEndpointDelete(t *testing.T) {

	assertCorrectMessage := func(t testing.TB, get, want string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("DELETE", "/oauth/keys/clientname99", nil)

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("kid", "clientname99")

		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
		handlers := http.HandlerFunc(bs.KeyEndpoint)

		handlers(w, r)
		t.Error()
	}
	t.Run("Registration Test 1", func(t *testing.T) {
		got := ""

		assertCorrectMessage(t, got, got)
	})

}

func TestGetRedirect(t *testing.T) {
	assertCorrectMessage := func(t testing.TB, got, want map[string]interface{}) {
		t.Helper()
		form := url.Values{}
		form.Add("name", "tester")
		form.Add("password", "testpw")
		req, err := http.NewRequest("POST", "/oauth/auth?client_id=ww&nonce=ww&response_type=id_token&scope=ww&redirect_uri=www.url.de&state=ww", bytes.NewBufferString(form.Encode()))
		//req.PostForm = form
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Fatal(err)
		}
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(bs.GetRedirect)

		//call ServeHTTP method and pass  Request and ResponseRecorder.
		handler.ServeHTTP(rr, req)
		bodybytes := rr.Header().Get("Location")
		if bodybytes == "" {
			t.Errorf("json encoding failed %v", err)
		}

	}
	t.Error()
	t.Run("Registration Test 1", func(t *testing.T) {
		got := map[string]interface{}{"name": "tester"}
		want := map[string]interface{}{"name": "tester"}
		assertCorrectMessage(t, got, want)
	})

}

func TestUserData(t *testing.T) {
	groups := []string{"Admin", "User"}
	s := make([]interface{}, len(groups))
	for i, v := range groups {
		s[i] = v
	}
}

func TestGetBearerToken(t *testing.T) {
	t.Run("Registration Test 2", func(t *testing.T) {
		accessToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwOTAyMjEyLTZjNmMtNDUyYi1iNGIzLTJkMDA0MTFhNjczMyIsInR5cCI6IkpXVCJ9.eyJmb28iOiJjbiIsIm5vbmNlIjoiY29kZSIsImdyb3VwcyI6WyIiXSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODI4MCIsInN1YiI6ImR3aWdodCIsImF1ZCI6WyJjbGllbnRuYW1lMyJdLCJleHAiOjE2NzY2NjU1MDMsIm5iZiI6MTY3NjU3OTEwMSwiaWF0IjoxNjc2NTc5MTAzLCJqdGkiOiIxIn0.RnTzphSAbXyO-IRFPf_MrdYsTxvLTmRR6GTVxnARQ-HCDYUAsJpVjMoBk0JvvbZs_tsseruF1vJY6qYycX2iNkY-9ehCzuNcB_uAE1nVdZWT7AeCkJAtCve3qq2xW7QbDeAK-UHue12tsXPeXS-Safi_iLKWHkl1MokqjAnmpL0oVC5jfKoG-UKzMOpxHnMrN4KjljW8JjFrJlH7hDJw8_mG2p1g_fNUJZ3EMRCBacCUUmG-Vi-Br7fu491FgNlHwybZTFPD7cr2I10m73JkQ2ZB1cAoIg2GEbQ2fp-UzljB1RncMCvGo1ieckbkxgtxEb3JMUsKd0-_rkSh74Ciow"
		got, err := GetJwtHeader(accessToken)
		if err != nil {
			t.Error(err)
		}
		want := JWT{Alg: "RS256", Kid: "20902212-6c6c-452b-b4b3-2d00411a6733"}
		iasserts.AssertGeneric(t, got, want)
	})
}

func TestUserInfo(t *testing.T) {
	//pass request to handler with nil as parameter
	req, err := http.NewRequest("GET", "/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiJhbGljZSIsImVtYWlsIjoiYWxpY2VAd29uZGVybGFuZC5uZXQiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIEFkYW1zIiwiYXVkIjoiMDAwMTIzIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL2MyaWQiLCJmYW1pbHlfbmFtZSI6IkFkYW1zIiwiaWF0IjoxNDEzOTg1NDAyLCJncm91cHMiOlsiYWRtaW4iLCJhdWRpdCJdfQ.FJv9UnxvQxYvlc2F_v657SIyZkjQ382Bc108O--UFh3cvkjxiO5P2sJyvcqfuGrlzgvU7gCKzTIqqrV74EcHwGb_xyBUPOKuIJGaDKirBdnPbIXMDGpSqmBQes4tc6L8pkhZfRENIlmkP-KphI3wPd4jtko2HXAdDFVjzK-FPic")
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.UserInfo)

	//call ServeHTTP method and pass  Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	bodybytes := rr.Body
	decoder := json.NewDecoder(bodybytes)
	var tsa map[string]interface{}
	err = decoder.Decode(&tsa)
	if err != nil {
		panic(err)
	}
	fmt.Println(tsa)
	fmt.Println("eree")
	//t.Error()

}

func TestGetHeaderAuth(t *testing.T) {

	t.Run("Authheader Success", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/userinfo", nil)
		if err != nil {
			t.Fatal(err)
		}

		want := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiJhbGljZSIsImVtYWlsIjoiYWxpY2VAd29uZGVybGFuZC5uZXQiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIEFkYW1zIiwiYXVkIjoiMDAwMTIzIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWxob3N0OjgwODBcL2MyaWQiLCJmYW1pbHlfbmFtZSI6IkFkYW1zIiwiaWF0IjoxNDEzOTg1NDAyLCJncm91cHMiOlsiYWRtaW4iLCJhdWRpdCJdfQ.FJv9UnxvQxYvlc2F_v657SIyZkjQ382Bc108O--UFh3cvkjxiO5P2sJyvcqfuGrlzgvU7gCKzTIqqrV74EcHwGb_xyBUPOKuIJGaDKirBdnPbIXMDGpSqmBQes4tc6L8pkhZfRENIlmkP-KphI3wPd4jtko2HXAdDFVjzK-FPic"
		req.Header.Add("Authorization", "Bearer "+want)
		rr := httptest.NewRecorder()
		got, err := getHeader("Authorization", rr, req)

		if err != nil {
			t.Error()
		}
		iasserts.AssertString(t, got, want)
		//.AssertString(t, got, want)
	})

	t.Run("Authheader fail", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/userinfo", nil)
		if err != nil {
			t.Fatal(err)
		}

		want := ""
		req.Header.Add("Authorization", "Bearer")
		rr := httptest.NewRecorder()
		got, err := getHeader("Authorization", rr, req)

		if err == nil {
			t.Error()
		}
		iasserts.AssertString(t, got, want)
		//.AssertString(t, got, want)
	})

}
