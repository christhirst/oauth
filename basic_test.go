package oauth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestA(t *testing.T) {
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()
	http.Get(slowServer.URL)

}

func TestGetBasicAuthentication(t *testing.T) {

	httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password123456")))
		username, password, err := GetBasicAuthentication(r)

		if err != nil {
			t.Fatalf("Error %s", err.Error())
		} else {
			if username != "admin" {
				t.Fatalf("Wrong Username = %s", username)
			}
			if password != "password123456" {
				t.Fatalf("Wrong Username = %s", password)
			}
		}

	}))
}

func TestVoidBasicAuthentication(t *testing.T) {
	req, _ := http.NewRequest("GET", "/token", nil)

	username, password, err := GetBasicAuthentication(req)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	} else {
		if username != "" {
			t.Fatalf("Wrong Username = %s", username)
		}
		if password != "" {
			t.Fatalf("Wrong Username = %s", password)
		}
	}

}

func TestCheckBasicAuthentication(t *testing.T) {
	req, _ := http.NewRequest("GET", "/token", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password123456")))

	err := CheckBasicAuthentication("admin", "password123456", req)
	if err != nil {
		t.Fatalf("Error %s", err.Error())
	} else {
		t.Log("Credentials are OK")
	}
}
