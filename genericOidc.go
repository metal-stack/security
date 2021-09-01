package security

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"
	"gopkg.in/square/go-jose.v2/jwt"
)

// GenericOIDCClaims
// https://openid.net/specs/openid-connect-core-1_0.html
// Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
type GenericOIDCClaims struct {
	jwt.Claims
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	EMail             string   `json:"email"`
	Roles             []string `json:"roles"`
}

func (g *GenericOIDCClaims) Username() string {
	if g.PreferredUsername != "" {
		return g.PreferredUsername
	}
	return g.Name
}

// GenericOIDC is Token Validator and UserGetter for Tokens issued by generic OIDC-Providers.
type GenericOIDC struct {
	issuerConfig    *IssuerConfig
	userExtractorFn GenericUserExtractorFn
	provider        *oidc.Provider
	verifier        *oidc.IDTokenVerifier
}

// GenericOIDCCfg properties that can be modified by Options
type GenericOIDCCfg struct {
	SupportedSigningAlgs []string
	Timeout              time.Duration
	UserExtractorFn      GenericUserExtractorFn
}

// NewGenericOIDC creates a new GenericOIDC.
func NewGenericOIDC(ic *IssuerConfig, opts ...GenericOIDCOption) (*GenericOIDC, error) {

	cfg := &GenericOIDCCfg{
		UserExtractorFn:      DefaultGenericUserExtractor,
		Timeout:              10 * time.Second,
		SupportedSigningAlgs: []string{"RS256", "RS384", "RS512"},
	}

	for _, opt := range opts {
		opt(cfg)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		Timeout: cfg.Timeout,
	}
	ctx := context.Background()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	provider, err := oidc.NewProvider(ctx, ic.Issuer)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:             ic.ClientID,
		SupportedSigningAlgs: cfg.SupportedSigningAlgs,
		SkipClientIDCheck:    false,
		SkipExpiryCheck:      false,
		SkipIssuerCheck:      false,
		Now:                  nil,
	})

	g := &GenericOIDC{
		issuerConfig:    ic,
		userExtractorFn: cfg.UserExtractorFn,
		provider:        provider,
		verifier:        verifier,
	}

	return g, nil
}

// User implements the UserGetter to get a user from the request.
func (o *GenericOIDC) User(rq *http.Request) (*User, error) {
	rawIDToken, err := ExtractBearer(rq)
	if err != nil {
		return nil, err
	}
	return o.UserFromToken(rawIDToken)
}

// UserFromToken implements the UserGetter to get a user from a jwt token.
func (o *GenericOIDC) UserFromToken(token string) (*User, error) {
	ctx := context.Background()

	// Parse and verify ID Token payload.
	idToken, err := o.verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	// Extract custom claims
	var claims GenericOIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	u, err := o.userExtractorFn(o.issuerConfig, &claims)
	if err != nil {
		return nil, err
	}

	return u, nil
}

// GenericOIDCOption provides means to configure GenericOIDC
type GenericOIDCOption func(oidc *GenericOIDCCfg)

// AllowedSignAlgs configures the allowed SigningAlgorithms, e.g. RS256, RS512,...
func AllowedSignAlgs(algs []string) GenericOIDCOption {
	return func(o *GenericOIDCCfg) {
		o.SupportedSigningAlgs = algs
	}
}

func Timeout(timeout time.Duration) GenericOIDCOption {
	return func(o *GenericOIDCCfg) {
		o.Timeout = timeout
	}
}

// GenericUserExtractorFn extracts the User and Claims
type GenericUserExtractorFn func(ic *IssuerConfig, claims *GenericOIDCClaims) (*User, error)

// GenericUserExtractor configures the GenericUserExtractorFn to extract the User from a token
func GenericUserExtractor(fn GenericUserExtractorFn) GenericOIDCOption {
	return func(o *GenericOIDCCfg) {
		o.UserExtractorFn = fn
	}
}

// DefaultGenericUserExtractor is the default implementation of how to extract
// the User from the token.
func DefaultGenericUserExtractor(ic *IssuerConfig, claims *GenericOIDCClaims) (*User, error) {
	var grps []ResourceAccess
	for _, g := range claims.Roles {
		grps = append(grps, ResourceAccess(g))
	}

	usr := User{
		Issuer:  claims.Issuer,
		Subject: claims.Subject,
		Name:    claims.Username(),
		EMail:   claims.EMail,
		Groups:  grps,
		Tenant:  ic.Tenant,
	}
	return &usr, nil
}
