package security

import (
	"net/http"

	jose "gopkg.in/square/go-jose.v2/jwt"
)

// UserGetterProxy switches between UserGetters depending on issuer/clientid of the token in the request.
type UserGetterProxy struct {
	ugs       map[string]UserGetter
	defaultUG UserGetter
}

// UserGetterProxyOption defines the signature of init option-parameter
type UserGetterProxyOption func(ug *UserGetterProxy)

// NewUserGetterProxy creates a new UserGetterProxy with the given default UserGetter which is
// used if no other match is found.
func NewUserGetterProxy(defaultUG UserGetter, opts ...UserGetterProxyOption) *UserGetterProxy {
	ugp := &UserGetterProxy{
		ugs:       make(map[string]UserGetter),
		defaultUG: defaultUG,
	}

	for _, o := range opts {
		o(ugp)
	}

	return ugp
}

// UserGetterProxyMapping adds the given UserGetter for the specified issuer/clientid combination that takes precedence
// over the default UserGetter if matched.
func UserGetterProxyMapping(issuer, clientid string, userGetter UserGetter) UserGetterProxyOption {
	return func(ug *UserGetterProxy) {
		ug.ugs[cacheKey(issuer, clientid)] = userGetter
	}
}

func (u *UserGetterProxy) User(rq *http.Request) (*User, error) {
	claims, err := ParseTokenClaimsUnvalidated(rq)
	if err != nil {
		return nil, err
	}

	ug, err := u.userFromClaims(claims)
	if err != nil {
		return nil, err
	}
	return ug.User(rq)
}

func (u *UserGetterProxy) UserFromToken(token string) (*User, error) {
	claims, err := ParseRawTokenClaimsUnvalidated(token)
	if err != nil {
		return nil, err
	}
	ug, err := u.userFromClaims(claims)
	if err != nil {
		return nil, err
	}
	return ug.UserFromToken(token)
}

func (u *UserGetterProxy) userFromClaims(claims *jose.Claims) (UserGetter, error) {
	issuer := claims.Issuer
	aud := claims.Audience

	var ug UserGetter
	for _, clientID := range aud {
		ug = u.ugs[cacheKey(issuer, clientID)]
		if ug != nil {
			break
		}
	}
	if ug == nil {
		ug = u.defaultUG
	}

	if ug == nil {
		return nil, nil
	}
	return ug, nil
}
