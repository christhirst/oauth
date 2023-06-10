package oauth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
)

type Cookie struct {
	Name       string
	Value      string
	Path       string
	Domain     string
	Expires    time.Time
	RawExpires string

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge   int
	Secure   bool
	HttpOnly bool
	Raw      string
	Unparsed []string // Raw text of unparsed attribute-value pairs
}

// Generate token response
func (bs *BearerServer) GenerateIdTokenResponse(codeCheck CodeCheck, method, iss string, aud []string, grantType GrantType, refreshToken string, code string, redirectURI string, at AuthToken, w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	sub := codeCheck.User
	client_id := codeCheck.ClientId
	aud = append(aud, client_id)

	var resp *TokenResponse
	switch grantType {
	//--------------------------->to Function and RedirectAccess -->takes that func
	case AuthCodeGrant:
		nonce := codeCheck.Nonce
		groups, err := bs.Verifier.ValidateUser(sub, "secret", "", r)
		if err != nil {
			log.Err(err).Msg("Failed getting groups")
		}

		token, refresh, idtoken, err := bs.generateIdTokens("RS256", aud, UserToken, sub, nonce, groups, at, r)
		if err != nil {
			return "Token generation failed, check claims", http.StatusInternalServerError, err
		}

		if resp, err = bs.cryptIdTokens(token, refresh, idtoken, r); err != nil {
			return "Token generation failed, check security provider", http.StatusInternalServerError, err
		}
	case RefreshTokenGrant:
		refresh, err := bs.provider.DecryptRefreshTokens(refreshToken)
		if err != nil {
			return "Not authorized", http.StatusUnauthorized, err
		}

		token, refresh, err := bs.generateTokens(refresh.TokenType, refresh.Credential, refresh.Scope, r)
		if err != nil {
			return "Token generation failed", http.StatusInternalServerError, err
		}

		err = bs.Verifier.StoreTokenID(token.TokenType, refresh.Credential, token.ID, refresh.RefreshTokenID)
		if err != nil {
			return "Storing Token ID failed", http.StatusInternalServerError, err
		}

		if resp, err = bs.cryptTokens(token, refresh, r); err != nil {
			return "Token generation failed", http.StatusInternalServerError, err
		}
	default:
		return "Invalid grant_type", http.StatusBadRequest, nil
	}

	return resp, http.StatusOK, nil
}

func refreshToken(tokenId string, username string, tokenType TokenType) *RefreshToken {
	refreshToken := &RefreshToken{RefreshTokenID: uuid.Must(uuid.NewV4()).String(), TokenID: tokenId, CreationDate: time.Now().UTC(), Credential: username, TokenType: tokenType, Scope: "scope"}
	return refreshToken
}

func (bs *BearerServer) generateIdTokens(method string, aud []string, tokenType TokenType, username, nonce string, groups []string, at AuthToken, r *http.Request) (string, *RefreshToken, string, error) {
	var formData *FormList
	if nonce != "" {
		formData = &FormList{
			ClientID: aud[0],
			Nonce:    nonce,
		}
	} else {
		formData = &FormList{
			ClientID: aud[0],
		}
	}

	claims := bs.Verifier.CreateClaims(username, *formData, groups, r)

	token, _ := CreateJWT(method, claims, bs.Kc)
	idtoken, _ := CreateJWT(method, claims, bs.Kc)
	refreshToken := refreshToken(aud[0], username, tokenType)
	fmt.Println(token)
	fmt.Println(idtoken)
	fmt.Println(refreshToken)

	return token, refreshToken, idtoken, nil
}

func (bs *BearerServer) cryptIdTokens(token string, refresh *RefreshToken, idToken string, r *http.Request) (*TokenResponse, error) {
	cRefreshToken, err := bs.provider.CryptRefreshToken(refresh)
	if err != nil {
		return nil, err
	}
	tokenResponse := &TokenResponse{Token: token, RefreshToken: cRefreshToken, TokenType: BearerToken, ExpiresIn: (int64)(bs.TokenTTL / time.Second), IDtoken: idToken}

	/* if bs.Verifier != nil {
		props, err := bs.Verifier.AddProperties(token.TokenType, token.Credential, token.ID, token.Scope, r)
		if err != nil {
			return nil, err
		}
		tokenResponse.Properties = props
	} */
	return tokenResponse, err
}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	err := binary.Write(bytesBuffer, binary.BigEndian, x)
	if err != nil {
		log.Err(err)
	}
	return bytesBuffer.Bytes()
}
