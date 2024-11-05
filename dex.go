package security

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	refetchInterval = 10 * time.Minute
)

type updater struct {
	updated chan jwk.Set
}

// A Dex ...
type Dex struct {
	baseURL         string
	keys            chan<- keyRQ
	update          chan updater
	refreshInterval time.Duration

	algorithmWhitelist []string

	userExtractor UserExtractorFn

	jwtParserOptions []jwt.ParserOption
}

type keyRsp struct {
	keys jwk.Set
	err  error
}
type keyRQ struct {
	rsp chan<- keyRsp
}

// NewDex returns a new Dex.
func NewDex(baseurl string) (*Dex, error) {
	dx := &Dex{
		baseURL:         baseurl,
		refreshInterval: refetchInterval,
		userExtractor:   defaultUserExtractor,

		algorithmWhitelist: []string{"RS256", "RS512"},
	}
	if err := dx.keyfetcher(); err != nil {
		return nil, err
	}
	return dx, nil
}

// Option configures Dex
type Option func(dex *Dex) *Dex

// With sets available Options
func (dx *Dex) With(opts ...Option) *Dex {
	for _, opt := range opts {
		opt(dx)
	}
	return dx
}

// Claims we overwrite the Audience because in the current version of the jwt library this
// is not an array.
type Claims struct {
	jwt.RegisteredClaims
	Audience        any               `json:"aud,omitempty"`
	Groups          []string          `json:"groups"`
	EMail           string            `json:"email"`
	Name            string            `json:"name"`
	FederatedClaims map[string]string `json:"federated_claims"`

	// added for parsing of "new" style tokens
	Roles []string `json:"roles"`
}

// UserExtractorFn extracts the User and Claims
type UserExtractorFn func(claims *Claims) (*User, error)

// UserExtractor extracts the user with the given extractorfunc
func UserExtractor(fn UserExtractorFn) Option {
	return func(dex *Dex) *Dex {
		dex.userExtractor = fn
		return dex
	}
}

// AlgorithmsWhitelist adds given algorithms as allowed
func AlgorithmsWhitelist(algNames []string) Option {
	return func(dex *Dex) *Dex {
		dex.algorithmWhitelist = algNames
		return dex
	}
}

func JWTParserOptions(opt jwt.ParserOption) Option {
	return func(dex *Dex) *Dex {
		dex.jwtParserOptions = append(dex.jwtParserOptions, opt)
		return dex
	}
}

func (dx *Dex) algorithmSupported(alg string) bool {
	for _, a := range dx.algorithmWhitelist {
		if a == alg {
			return true
		}
	}
	return false
}

// the keyfetcher fetches the keys from the remote dex at a regular interval.
// if the client needs the keys it returns the cached keys.
func (dx *Dex) keyfetcher() error {
	c := make(chan keyRQ)
	dx.keys = c
	dx.update = make(chan updater)
	keys, err := jwk.Fetch(context.Background(), dx.baseURL+"/keys")
	if err != nil {
		return fmt.Errorf("cannot fetch dex keys from %s/keys: %w", dx.baseURL, err)
	}
	t := time.NewTicker(dx.refreshInterval)
	go func() {
		defer close(c)
		defer t.Stop()
		for {
			select {
			case keyRQ := <-c:
				keyRQ.rsp <- keyRsp{keys, err}
			case <-t.C:
				keys, err = dx.updateKeys(keys)
			case u := <-dx.update:
				keys, err = dx.updateKeys(keys)
				u.updated <- keys
			}
		}
	}()
	return nil
}

// fetchKeys asks the current keyfetcher to give the current keyset
func (dx *Dex) fetchKeys() (jwk.Set, error) {
	outchan := make(chan keyRsp)
	krq := keyRQ{rsp: outchan}
	defer close(krq.rsp)
	dx.keys <- krq
	rsp := <-outchan
	return rsp.keys, rsp.err
}

func (dx *Dex) forceUpdate() {
	u := updater{
		updated: make(chan jwk.Set),
	}
	defer close(u.updated)
	dx.update <- u
	<-u.updated
}

func (dx *Dex) updateKeys(old jwk.Set) (jwk.Set, error) {
	k, e := jwk.Fetch(context.Background(), dx.baseURL+"/keys")
	if e != nil {
		return old, fmt.Errorf("cannot fetch dex keys from %s/keys: %w", dx.baseURL, e)
	}
	return k, e
}

// searchKey searches the given key in the set loaded from dex. If
// there is a key it will be returned otherwise an error is returned
func (dx *Dex) searchKey(kid string) (any, error) {
	for i := 0; i < 2; i++ {
		keys, err := dx.fetchKeys()
		if err != nil {
			return nil, err
		}
		jwtkey, ok := keys.LookupKeyID(kid)
		if !ok {
			dx.forceUpdate()
			continue
		}
		var key any
		err = jwtkey.Raw(&key)
		return key, err
	}
	return nil, fmt.Errorf("key %q not found", kid)
}

// User implements the UserGetter to get a user from the request.
func (dx *Dex) User(rq *http.Request) (*User, error) {
	auth := rq.Header.Get("Authorization")
	if auth == "" {
		return nil, errNoAuthFound
	}
	splitToken := strings.Split(auth, "Bearer")
	if len(splitToken) < 2 {
		// no Bearer token
		return nil, errNoAuthFound
	}
	bearerToken := strings.TrimSpace(splitToken[1])

	token, err := jwt.ParseWithClaims(bearerToken, &Claims{}, func(token *jwt.Token) (any, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, errors.New("invalid token")
		}
		if !dx.algorithmSupported(alg) {
			return nil, errors.New("invalid token")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("invalid token")
		}
		return dx.searchKey(kid)
	}, dx.jwtParserOptions...)
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return dx.userExtractor(claims)
	}
	return nil, errors.New("invalid claims")
}

func defaultUserExtractor(claims *Claims) (*User, error) {
	if claims == nil {
		return nil, errors.New("claims is nil")
	}
	var grps []ResourceAccess
	for _, g := range claims.Groups {
		grps = append(grps, ResourceAccess(g))
	}
	tenant := ""
	if claims.FederatedClaims != nil {
		cid := claims.FederatedClaims["connector_id"]
		if cid != "" {
			tenant = strings.Split(cid, "_")[0]
		}
	}
	usr := User{
		Issuer:  claims.Issuer,
		Subject: claims.Subject,
		Name:    claims.Name,
		EMail:   claims.EMail,
		Groups:  grps,
		Tenant:  tenant,
	}
	return &usr, nil
}
