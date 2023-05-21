package oauth

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var scheme = "https://"

type TokenType string

const (
	BearerToken TokenType = "Bearer"
	AuthTokent  TokenType = "A"
	UserToken   TokenType = "U"
	ClientToken TokenType = "C"
)

type postData struct {
	Key   string
	Value string
}

type ConnDataLdap struct {
	LdapName     string
	Owner        []string
	Hostname     string
	Port         int
	Bindusername string
	Bindpassword string
	Starttls     bool
	Filter       string
	Basedn       string
	Uid          string
	SyncMode     string
	Mapping      bool
	Frequence    int64
	SCIM         bool
	SPN          string
	IPRange      string
}

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
	Code_challenge_methods_supported              []string `json:"code_challenge_methods_supported,omitempty"`
	Introspection_endpoint                        string   `json:"introspection_endpoint,omitempty"`
	Introspection_endpoint_auth_methods_supported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	Revocation_endpoint                           string   `json:"revocation_endpoint,omitempty"`
	Revocation_endpoint_auth_methods_supported    []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	End_session_endpoint                          string   `json:"end_session_endpoint,omitempty"`
	Request_parameter_supported                   bool     `json:"request_parameter_supported,omitempty"`
	Request_object_signing_alg_values_supported   []string `json:"request_object_signing_alg_values_supported,omitempty"`
}

type TokenRequest struct {
	Token string `json:"token"`
}

// TokenResponse is the authorization server response
type TokenResponse struct {
	Token        string            `json:"access_token"`
	TokenType    TokenType         `json:"token_type"` // bearer
	RefreshToken string            `json:"refresh_token"`
	ExpiresIn    int64             `json:"expires_in"` // secs
	Properties   map[string]string `json:"properties"`
	IDtoken      string            `json:"id_token"`
	Scope        string            `json:"scope"`
}

type MyCustomClaims struct {
	Foo    string   `json:"foo"`
	Nonce  string   `json:"nonce"`
	Groups []string `json:"groups"`
	jwt.RegisteredClaims
}

//idToken

type MyCustomClaimss struct {
	Iss       string   `json:"iss"`
	Sub       string   `json:"sub"`
	Nonce     string   `json:"nonce"`
	Aud       []string `json:"aud"`
	Azp       string   `json:"azp"`
	Client_id string   `json:"client_id"`
	Scope     []string `json:"scope"`
	Groups    []string `json:"groups"`
	jwt.RegisteredClaims
}

type UserInfo struct {
	Sub                   string   `json:"sub"`
	Name                  string   `json:"name"`
	Given_name            string   `json:"given_name"`
	Family_name           string   `json:"family_name"`
	Middle_name           string   `json:"middle_name"`
	Nickname              string   `json:"nickname"`
	Preferred_username    string   `json:"preferred_username"`
	Profile               string   `json:"profile"`
	Picture               string   `json:"picture"`
	Website               string   `json:"website"`
	Email                 string   `json:"email"`
	Email_verified        string   `json:"email_verified"`
	Gender                string   `json:"gender"`
	Birthdate             string   `json:"birthdate"`
	Zoneinfo              string   `json:"zoneinfo"`
	Locale                string   `json:"locale"`
	Phone_number          string   `json:"phone_number"`
	Phone_number_verified string   `json:"phone_number_verified"`
	Address               []string `json:"address"`
	Updated_at            string   `json:"updated_at"`
	Nonce                 string   `json:"nonce"`
	Groups                []string `json:"groups"`
}

type IntroSpectReturn struct {
	Active     string   `json:"active"`
	Scope      []string `json:"scope"`
	Client_id  string   `json:"client_id"`
	Username   string   `json:"username"`
	Token_type string   `json:"token_type"`
	Exp        string   `json:"exp"`
	Iat        string   `json:"iat"`
	Nbf        string   `json:"nbf"`
	Sub        string   `json:"sub"`
	Aud        string   `json:"aud"`
	Iss        string   `json:"iss"`
	Jti        string   `json:"jti"`
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
	Aud          []string          `json:"aud"`
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

type AuthToken struct {
	Foo string `json:"foo"`
	jwt.RegisteredClaims
	Iss       string           `json:"iss"`
	Sub       string           `json:"sub"`
	Aud       []string         `json:"aud"`
	Nonce     string           `json:"nonce"`
	Exp       *jwt.NumericDate `json:"exp"`
	Iat       string           `json:"iat"`
	Jti       string           `json:"jti"`
	Client_id string           `json:"client_id"`
	Scope     []string         `json:"scope"`
	Auth_time string
	Acr       string
	Azp       string
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

/* type User struct {
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

} */

type Keys struct {
	Keys []map[string]string `json:"keys"`
}

type KeyContainer struct {
	Pk map[string]*rsa.PrivateKey
	//Pk   *rsa.PrivateKey
	Keys Keys
}

/*
	 type RedirectParameter struct {
		code          string
		state         string
		nonce         string
		response_type string
		scope         string
		redirect_uri  string
		client_id     string
		username      string
		credential    string
	}
*/

type Mapping struct {
	Client_name string                `json:"client_name,omitempty"`
	Mapping     []map[string][]string `json:"mapping,omitempty"`
}

type Registration struct {
	Client_id                       string   `json:"client_id,omitempty"`
	Owner                           []string `json:"Owner,omitempty"`
	Client_secret                   string   `json:"client_secret,omitempty"`
	Kid                             string   `json:"kid,omitempty"`
	Redirect_uris                   []string `json:"redirect_uris,omitempty"`
	Response_types                  string   `json:"response_types,omitempty"`
	Grant_types                     string   `json:"grant_types,omitempty"`
	Application_type                string   `json:"application_type,omitempty"`
	Contacts                        []string `json:"contacts,omitempty"`
	Client_name                     string   `json:"client_name,omitempty"`
	Logo_uri                        string   `json:"logo_uri,omitempty"`
	Client_uri                      string   `json:"client_uri,omitempty"`
	Policy_uri                      string   `json:"policy_uri,omitempty"`
	Tos_uri                         string   `json:"tos_uri,omitempty"`
	Jwks_uri                        string   `json:"jwks_uri,omitempty"`
	Jwks                            string   `json:"jwks,omitempty"`
	Sector_identifier_uri           string   `json:"sector_identifier_uri,omitempty"`
	Subject_type                    string   `json:"subject_type,omitempty"`
	Id_token_signed_response_alg    string   `json:"id_token_signed_response_alg,omitempty"`
	Id_token_encrypted_response_alg string   `json:"id_token_encrypted_response_alg,omitempty"`
	Id_token_encrypted_response_enc string   `json:"id_token_encrypted_response_enc,omitempty"`
	Userinfo_signed_response_alg    string   `json:"userinfo_signed_response_alg,omitempty"`
	Userinfo_encrypted_response_alg string   `json:"userinfo_encrypted_response_alg,omitempty"`
	Userinfo_encrypted_response_enc string   `json:"userinfo_encrypted_response_enc,omitempty"`
	Request_object_signing_alg      string   `json:"request_object_signing_alg,omitempty"`
	Request_object_encryption_alg   string   `json:"request_object_encryption_alg,omitempty"`
	Request_object_encryption_enc   string   `json:"request_object_encryption_enc,omitempty"`
	Token_endpoint_auth_method      string   `json:"token_endpoint_auth_method,omitempty"`
	Token_endpoint_auth_signing_alg string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	Default_max_age                 string   `json:"default_max_age,omitempty"`
	Require_auth_time               string   `json:"require_auth_time,omitempty"`
	Default_acr_values              string   `json:"default_acr_values,omitempty"`
	Initiate_login_uri              string   `json:"initiate_login_uri,omitempty"`
	Request_uris                    string   `json:"request_uris,omitempty"`
	Registration_access_token       string   `json:"registration_access_token,omitempty"`
}

type K struct {
	Ke string `json:"ke"`
	Le string
}
type Federation struct {
	Auth  string
	Store string
}
type AuthTarget struct {
	Participant map[string]Federation
}

type CodeCheck struct {
	Code     string
	User     string
	Nonce    string
	ClientId string
}
