package oauth

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/christhirst/gohelper/iasserts"
)

func TestFormExtractor(t *testing.T) {
	formList := []string{"name", "password", "client_id", "response_type", "redirect_uri", "scope", "nonce", "state"}
	formMap := map[string][]string{"name": {"name"}, "password": {"password"}, "client_id": {"client_id"},
		"response_type": {"response_type"}, "redirect_uri": {"redirect_uri"}, "nonce": {"nonce"},
		"state": {"state"}, "scope": {"scope", "openid"}}
	form := url.Values{}

	t.Run("Registration Test 1", func(t *testing.T) {
		want := map[string][]string{"name": {"name"}, "password": {"password"}, "client_id": {"client_id"},
			"response_type": {"response_type"}, "redirect_uri": {"redirect_uri"}, "nonce": {"nonce"},
			"state": {"state"}, "scope": {"scope", "openid"}}

		req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		QueryAddList(req, formMap)
		if err != nil {
			t.Error(err)
		}
		got, err := UrlExtractor(req, formList)
		if err != nil {
			t.Error(err)
		}
		iasserts.AssertCorrectMessage(t, got, want)
	})

	t.Run("Registration Test 2", func(t *testing.T) {
		formAddList(&form, formMap)
		want := map[string][]string{"name": {"name"}, "password": {"password"}, "client_id": {"client_id"},
			"response_type": {"response_type"}, "redirect_uri": {"redirect_uri"}, "nonce": {"nonce"},
			"state": {"state"}, "scope": {"scope", "openid"}}

		req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Error(err)
		}
		got, _, err := formExtractor(req, formList)
		if err != nil {
			t.Error(err)
		}
		iasserts.AssertCorrectMessage(t, got, want)
	})

	t.Run("Registration Test 3", func(t *testing.T) {
		formAddList(&form, formMap)
		want := []string{"scope"}
		form.Del(want[0])
		req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			t.Error(err)
		}
		_, got, err := formExtractor(req, formList)
		if err != nil {
			t.Error(err)
		}

		iasserts.AssertGeneric(t, got[0], want[0])
	})

}

func TestFillStruct(t *testing.T) {
	type TestStruct struct {
		StringField string
		SliceField  []string
	}

	values := map[string][]string{
		"StringField": {"hello"},
		"SliceField":  {"foo", "bar", "baz"},
	}

	expected := TestStruct{
		StringField: "hello",
		SliceField:  []string{"foo", "bar", "baz"},
	}

	var actual TestStruct
	err := FillStruct(&actual, values)
	if err != nil {
		t.Errorf("fillStruct returned an error: %v", err)
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("fillStruct returned unexpected result: got %v, want %v", actual, expected)
	}
}
