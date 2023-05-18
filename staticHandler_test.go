package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenidConfig(t *testing.T) {
	bs := &BearerServer{}
	req, err := http.NewRequest("GET", "/openid-configuration", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(bs.OpenidConfig)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := rr.Body.String()

	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}
