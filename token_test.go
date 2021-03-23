package security

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/stretchr/testify/assert"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestCreateTokenAndKeys(t *testing.T) {

	algs := []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
	}

	for _, alg := range algs {
		t.Run(string(alg), func(t *testing.T) {

			clientID := "myClient"
			tc := &TokenCfg{
				Alg:           alg,
				IssuerUrl:     "http://metal-stack.io",
				Audience:      jwt.Audience{"aud1", "aud2", clientID},
				ExpiresAt:     time.Now().Add(5 * time.Minute),
				IssuedAt:      time.Now(),
				Id:            "#123abc",
				Subject:       "theSubject",
				Name:          "theName",
				PreferredName: "thePreferredName",
				Email:         "me@metal-stack.io",
				Roles:         []string{"role1", "r-o-l-e-2", "r$o$l$e-3"},
			}

			srv, token, err := GenerateTokenAndKeyServer(tc, func(cfg *TokenCfg) (string, jose.JSONWebKey, jose.JSONWebKey) {
				return MustCreateTokenAndKeys(tc)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()

			ic := &IssuerConfig{
				Annotations: map[string]string{},
				Tenant:      "Tn",
				Issuer:      srv.URL,
				ClientID:    clientID,
			}

			oidc, err := NewGenericOIDC(ic, AllowedSignAlgs([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}))
			if err != nil {
				t.Fatal(err)
			}

			rq := &http.Request{
				Header: createHeader(AuthzHeaderKey, "Bearer "+token),
			}

			u, err := oidc.User(rq)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, u.Tenant, "Tn")
			assert.Equal(t, u.Name, tc.PreferredName)
			assert.Equal(t, u.EMail, tc.Email)

			var rr []ResourceAccess
			for _, r := range tc.Roles {
				rr = append(rr, ResourceAccess(r))
			}
			diff := cmp.Diff(u.Groups, rr)
			if diff != "" {
				t.Error(diff)
			}

		})
	}
}
