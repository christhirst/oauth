package oauth

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var scheme = "https://"

type TokenType string

const (
	BearerToken TokenType = "Bearer"
	AuthToken   TokenType = "A"
	UserToken   TokenType = "U"
	ClientToken TokenType = "C"
)

type OpenidConfig struct {
	Issuer                                        string   `json:"issuer"`
	Authorization_endpoint                        string   `json:"authorization_endpoint"`
	Token_endpoint                                string   `json:"token_endpoint"`
	Userinfo_endpoint                             string   `json:"userinfo_endpoint"`
	Registration_endpoint                         string   `json:"registration_endpoint"`
	Jwks_uri                                      string   `json:"jwks_uri"`
	Response_types_supported                      []string `json:"response_types_supported"`
	Response_modes_supported                      []string `json:"response_modes_supported"`
	Grant_types_supported                         []string `json:"grant_types_supported"`
	Subject_types_supported                       []string `json:"subject_types_supported"`
	Id_token_signing_alg_values_supported         []string `json:"id_token_signing_alg_values_supported"`
	Scopes_supported                              []string `json:"scopes_supported"`
	Token_endpoint_auth_methods_supported         []string `json:"token_endpoint_auth_methods_supported"`
	Claims_supported                              []string `json:"claims_supported"`
	Code_challenge_methods_supported              []string `json:"code_challenge_methods_supported"`
	Introspection_endpoint                        string   `json:"introspection_endpoint"`
	Introspection_endpoint_auth_methods_supported []string `json:"introspection_endpoint_auth_methods_supported"`
	Revocation_endpoint                           string   `json:"revocation_endpoint"`
	Revocation_endpoint_auth_methods_supported    []string `json:"revocation_endpoint_auth_methods_supported"`
	End_session_endpoint                          string   `json:"end_session_endpoint"`
	Request_parameter_supported                   bool     `json:"request_parameter_supported"`
	Request_object_signing_alg_values_supported   []string `json:"request_object_signing_alg_values_supported"`
}

// TokenResponse is the authorization server response
type TokenResponse struct {
	Token        string            `json:"access_token"`
	TokenType    TokenType         `json:"token_type"` // bearer
	RefreshToken string            `json:"refresh_token"`
	ExpiresIn    int64             `json:"expires_in"` // secs
	Properties   map[string]string `json:"properties"`
	IDtoken      string            `json:"id_token"`
}

type MyCustomClaims struct {
	Foo   string `json:"foo"`
	Nonce string `json:"nonce"`
	jwt.RegisteredClaims
}

// Token structure generated by the authorization server
type IDtoken struct {
	ID           string            `json:"id_token"`
	CreationDate time.Time         `json:"date"`
	ExpiresIn    time.Duration     `json:"expires_in"` // secs
	Credential   string            `json:"credential"`
	Scope        string            `json:"scope"`
	Claims       map[string]string `json:"claims"`
	TokenType    TokenType         `json:"type"`
	Issuer       string            `json:"issuer"`
	Subject      string            `json:"subject"`
	Audience     string            `json:"audience"`
	Expiration   time.Duration     `json:"expiration"`
}

type Token struct {
	ID           string            `json:"id_token"`
	CreationDate time.Time         `json:"date"`
	ExpiresIn    time.Duration     `json:"expires_in"` // secs
	Credential   string            `json:"credential"`
	Scope        string            `json:"scope"`
	Claims       map[string]string `json:"claims"`
	TokenType    TokenType         `json:"type"`
}

// RefreshToken structure included in the authorization server response
type RefreshToken struct {
	CreationDate   time.Time `json:"date"`
	TokenID        string    `json:"id_token"`
	RefreshTokenID string    `json:"id_refresh_token"`
	Credential     string    `json:"credential"`
	TokenType      TokenType `json:"type"`
	Scope          string    `json:"scope"`
}

type ClientConfig struct {
	Method string     `json:"method"`
	Claims jwt.Claims `json:"Claims"`
	Kid    string     `json:"kid"`
}
type Keys struct {
	Keys []map[string]string `json:"keys"`
}

type User struct {
	sub                string
	name               string
	given_name         string
	family_name        string
	middle_name        string
	nickname           string
	preferred_username string
	profile            string
	picture            string
	website            string
	email              string
	//[ email_verified ] {true|false} True if the end-user's email address has been verified, else false.
	//[ gender ] {"male"|"female"|?} The end-user's gender.
	//[ birthdate ] {string} The end-user's birthday, represented in ISO 8601:2004 YYYY-MM-DD format. The year may be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
	//zoneinfo string
	//[ locale ] {string} The end-user's locale, represented as a BCP47 language tag. This is typically an ISO 639-1 Alpha-2 language code in lowercase and an ISO 3166-1 Alpha-2 country code in uppercase, separated by a dash. For example, en-US or fr-CA.
	//[ phone_number ] {string} The end-user's preferred telephone number, typically in E.164 format, for example +1 (425) 555-1212 or +56 (2) 687 2400.
	//phone_number_verified bool
	//[ address ] {object} A JSON object describing the end-user's preferred postal address with any of the following members:
	//[ formatted ] {string} The full mailing address, with multiple lines if necessary. Newlines can be represented either as a \r\n or as a \n.
	//[ street_address ] {string} The street address component, which may include house number, stree name, post office box, and other multi-line information. Newlines can be represented either as a \r\n or as a \n.
	// [ locality ] {string} City or locality component.
	//[ region ] {string} State, province, prefecture or region component.
	//[ postal_code ] {string} Zip code or postal code component.
	// [ country ] {string} Country name component.
	// [ updated_at ] {number} Time the end-user's information was last updated, as number of seconds since the Unix epoch (1970-01-01T0:0:0Z) as measured in UTC until the date/time.

}
