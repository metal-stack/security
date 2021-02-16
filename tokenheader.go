package security

import (
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/square/go-jose.v2/jwt"
)

// ParseTokenClaimsUnvalidated returns the UNVALIDATED claims from the bearer token in the authentication header.
func ParseTokenClaimsUnvalidated(req *http.Request) (*jwt.Claims, error) {
	tokenString, err := ExtractBearer(req)
	if err != nil {
		return nil, err
	}

	// parse token unvalidated, extract claims that should always be present
	parsedClaims := &jwt.Claims{}
	webToken, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %s", err)
	}

	err = webToken.UnsafeClaimsWithoutVerification(parsedClaims)
	if err != nil {
		return nil, fmt.Errorf("error parsing token claims: %s", err)
	}

	return parsedClaims, nil
}

// ExtractBearer extracts the Bearer Token from the request header
func ExtractBearer(rq *http.Request) (string, error) {
	auth := rq.Header.Get(AuthzHeaderKey)
	if auth == "" {
		return "", errNoAuthFound
	}
	if len(auth) > 6 && strings.ToUpper(auth[0:7]) == "BEARER " {
		return auth[7:], nil
	}

	return "", errNoAuthFound
}
