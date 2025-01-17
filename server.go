package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/zekroTJA/timedmap"
)

type GrantType string

const (
	PasswordGrant          GrantType = "password"
	ClientCredentialsGrant GrantType = "client_credentials"
	AuthCodeGrant          GrantType = "authorization_code"
	RefreshTokenGrant      GrantType = "refresh_token"
)

// CredentialsVerifier defines the interface of the user and client credentials Verifier.
type CredentialsVerifier interface {
	// Validate username and password returning an error if the user credentials are wrong
	ValidateUser(username, password, scope string, r *http.Request) ([]string, error)
	// Get userdata and password returning an error if the user credentials are wrong

	GetUserData(username, scope string, r *http.Request) (map[string]interface{}, error)
	// Validate clientID and secret returning an error if the client credentials are wrong
	ValidateClient(clientID, clientSecret string) error
	// Provide additional claims to the token
	AddClaims(tokenType TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error)
	// Provide additional information to the authorization server response
	AddProperties(tokenType TokenType, credential, tokenID, scope string, r *http.Request) (map[string]string, error)
	// Optionally validate previously stored tokenID during refresh request
	ExtractJWTtoUserGroup(jwt string) ([]string, error)
	// Optionally store the tokenID generated for the user
	StoreTokenID(tokenType TokenType, credential, tokenID, refreshTokenID string) error
	// Provide additional claims to the idtoken
	//AddIdClaims() (map[string]string, error)
	// Provide additional claims to the idtoken
	CreateClaims(username string, formData FormList, groups []string, r *http.Request) MyCustomClaimss
	//CreateAtClaims(username, client_id string, aud []string, nonce string, scope, groups []string, at AuthToken, r *http.Request) MyCustomClaimss

	UserLookup(username string, scope []string) (map[string]string, []string, error)
	SessionGet(w http.ResponseWriter, r *http.Request, cookieID string) (string, bool, error)
	SessionSave(w http.ResponseWriter, r *http.Request, userID, cookieID string) (string, error)

	StoreClientDelete(client []string) error
	//StoreClient(clientname string, registration Registration, methode string) (*Registration, error)
	StoreClientGet(string) (*Registration, error)
	StoreClientsGet() (map[string]*Registration, error)
	//
	StoreKeyDelete(kid []string) error
	StoreKey(keyString map[string]string) error
	StoreKeysGet() (map[string]rsa.PrivateKey, error)
	StoreKeysAppend(jwks []map[string]string) []map[string]string

	SignInMethodK(h http.Handler, kt *keytab.Keytab, l *log.Logger, spn string, bs *BearerServer) http.Handler
	SignInMethod(clientId string, w http.ResponseWriter, r *http.Request) error
	SignAdminInMethod(clientId string, w http.ResponseWriter, r *http.Request) (bool, error)
}

// AuthorizationCodeVerifier defines the interface of the Authorization Code Verifier
type AuthorizationCodeVerifier interface {
	// ValidateCode checks the authorization code and returns the user credential
	ValidateCode(sub string, clientID, clientSecret, code, redirectURI string, r *http.Request) (string, error)
}

// BearerServer is the OAuth 2 bearer server implementation.
type BearerServer struct {
	secretKey string
	TokenTTL  time.Duration
	Verifier  CredentialsVerifier
	provider  *TokenProvider
	pKey      *rsa.PrivateKey
	Kc        *KeyContainer
	Signature string
	nonce     string
	Clients   map[string]*ClientConfig
	Tm        *timedmap.TimedMap
}

func (b *BearerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.SignIn(w, r)
}

// NewBearerServer creates new OAuth 2 bearer server
func NewBearerServer(secretKey string, ttl time.Duration, Verifier CredentialsVerifier, formatter TokenSecureFormatter) *BearerServer {
	privatekey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kc := KeyContainer{Pk: map[string]*rsa.PrivateKey{"test": privatekey}}
	GenJWKS(&kc)

	if formatter == nil {
		formatter = NewSHA256RC4TokenSecurityProvider([]byte(secretKey))
	}
	clients := InitClientConfig()
	tm := timedmap.New(5 * time.Second)
	return &BearerServer{
		secretKey: secretKey,
		Kc:        &kc,
		TokenTTL:  ttl,
		Verifier:  Verifier,
		provider:  NewTokenProvider(formatter),
		pKey:      privatekey,
		Clients:   clients,
		Tm:        tm,
	}
}

// AuthorizationCode manages authorization code grant type requests for the phase two of the authorization process
/* func (bs *BearerServer) AuthorizationCode(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	// grant_type client_credentials variables
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret") // not mandatory
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri") // not mandatory
	scope := r.FormValue("scope")              // not mandatory
	if clientID == "" {
		var err error
		clientID, clientSecret, err = GetBasicAuthentication(r)
		if err != nil {
			renderJSON(w, "Not authorized", http.StatusUnauthorized)
			return
		}
	}
	connection, err := bs.Verifier.GetConnectionTarget(w, r)
	if err != nil {
		log.Err(err)
	}
	resp, status := bs.generateTokenResponse(GrantType(grantType), clientID, clientSecret, "", scope, code, redirectURI, r)
	renderJSON(w, resp, status)
} */

// Generate token response
func (bs *BearerServer) generateTokenResponse(grantType GrantType, credential string, secret string, refreshToken string, scope string, code string, redirectURI string, r *http.Request) (interface{}, int) {
	var resp *TokenResponse
	switch grantType {
	case PasswordGrant:
		/* e, err := bs.Verifier.ValidateUser(credential, secret, scope, connection, r)
		if err != nil {
			log.Err(err)
		}
		if err := e; err != nil {
			return "Not authorized", http.StatusUnauthorized
		}
		*/
		token, refresh, err := bs.generateTokens(UserToken, credential, scope, r)
		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError
		}

		if err = bs.Verifier.StoreTokenID(token.TokenType, credential, token.ID, refresh.RefreshTokenID); err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError
		}

		if resp, err = bs.cryptTokens(token, refresh, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError
		}
	case ClientCredentialsGrant:
		if err := bs.Verifier.ValidateClient(credential, secret); err != nil {
			return "Not authorized", http.StatusUnauthorized
		}

		token, refresh, err := bs.generateTokens(ClientToken, credential, scope, r)
		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError
		}

		if err = bs.Verifier.StoreTokenID(token.TokenType, credential, token.ID, refresh.RefreshTokenID); err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError
		}

		if resp, err = bs.cryptTokens(token, refresh, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError
		}
	case AuthCodeGrant:
		codeVerifier, ok := bs.Verifier.(AuthorizationCodeVerifier)
		if !ok {
			return "Not authorized, grant type not supported", http.StatusUnauthorized
		}

		user, err := codeVerifier.ValidateCode("bs", credential, secret, code, redirectURI, r)
		if err != nil {
			return "Not authorized", http.StatusUnauthorized
		}

		token, refresh, err := bs.generateTokens(AuthTokent, user, scope, r)
		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError
		}

		err = bs.Verifier.StoreTokenID(token.TokenType, user, token.ID, refresh.RefreshTokenID)
		if err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError
		}

		if resp, err = bs.cryptTokens(token, refresh, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError
		}
	case RefreshTokenGrant:
		refresh, err := bs.provider.DecryptRefreshTokens(refreshToken)
		if err != nil {
			return "Not authorized", http.StatusUnauthorized
		}

		if _, err = bs.Verifier.ExtractJWTtoUserGroup(refreshToken); err != nil {

			return nil, 200
		}

		token, refresh, err := bs.generateTokens(refresh.TokenType, refresh.Credential, refresh.Scope, r)
		if err != nil {
			return "Token generation failed", http.StatusInternalServerError
		}

		err = bs.Verifier.StoreTokenID(token.TokenType, refresh.Credential, token.ID, refresh.RefreshTokenID)
		if err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError
		}

		if resp, err = bs.cryptTokens(token, refresh, r); err != nil {
			return "Token generation failed", http.StatusInternalServerError
		}
	default:
		return "Invalid grant_type", http.StatusBadRequest
	}

	return resp, http.StatusOK
}

func (bs *BearerServer) generateTokens(tokenType TokenType, username, scope string, r *http.Request) (*Token, *RefreshToken, error) {
	token := &Token{ID: uuid.Must(uuid.NewV4()).String(), Credential: username, ExpiresIn: bs.TokenTTL, CreationDate: time.Now().UTC(), TokenType: tokenType, Scope: scope}
	if bs.Verifier != nil {
		claims, err := bs.Verifier.AddClaims(token.TokenType, username, token.ID, token.Scope, r)
		if err != nil {
			return nil, nil, err
		}
		token.Claims = claims
	}

	refreshToken := &RefreshToken{RefreshTokenID: uuid.Must(uuid.NewV4()).String(), TokenID: token.ID, CreationDate: time.Now().UTC(), Credential: username, TokenType: tokenType, Scope: scope}

	return token, refreshToken, nil
}

func (bs *BearerServer) cryptTokens(token *Token, refresh *RefreshToken, r *http.Request) (*TokenResponse, error) {
	cToken, err := bs.provider.CryptToken(token)

	if err != nil {
		return nil, err
	}
	cRefreshToken, err := bs.provider.CryptRefreshToken(refresh)
	if err != nil {
		return nil, err
	}

	tokenResponse := &TokenResponse{Token: cToken, RefreshToken: cRefreshToken, TokenType: BearerToken, ExpiresIn: (int64)(bs.TokenTTL / time.Second), IDtoken: "sss"}

	if bs.Verifier != nil {
		props, err := bs.Verifier.AddProperties(token.TokenType, token.Credential, token.ID, token.Scope, r)
		if err != nil {
			return nil, err
		}
		tokenResponse.Properties = props
	}
	return tokenResponse, nil
}
