package security

import (
	"errors"
	"net/http"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/stretchr/testify/assert"

	"gopkg.in/square/go-jose.v2"
)

type wantUserFn func(issuer string) *User

func TestGenericOIDC_User(t *testing.T) {
	type args struct {
		tokenCfg      *TokenCfg
		issuerConfig  *IssuerConfig
		tokenProvider TokenProvider
		keyServerOpts []KeyServerOption
		requestFn     requestFn
	}
	tests := []struct {
		name                string
		args                args
		want                wantUserFn
		wantErrAtNew        error
		wantErrAtUserRegExp error
	}{
		{
			name: "Illegal issuer",
			args: args{
				tokenCfg: DefaultTokenCfg(),
				issuerConfig: &IssuerConfig{
					Tenant:   "Tn",
					Issuer:   "https://wrongIssuer", // will automagically be filled if empty
					ClientID: "abc",
				},
				tokenProvider: func(cfg *TokenCfg) (string, jose.JSONWebKey, jose.JSONWebKey) {
					return MustCreateTokenAndKeys(cfg)
				},
				requestFn: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "Bearer "+token),
					}
				},
			},
			want:         nil,
			wantErrAtNew: errors.New("Get \"https://wrongIssuer/.well-known/openid-configuration\": dial tcp: lookup wrongIssuer: no such host"),
		},
		{
			name: "Wrong audience",
			args: args{
				tokenCfg: DefaultTokenCfg(),
				issuerConfig: &IssuerConfig{
					Tenant:   "Tn",
					Issuer:   "", // will automagically be filled if empty
					ClientID: "abc",
				},
				tokenProvider: func(cfg *TokenCfg) (string, jose.JSONWebKey, jose.JSONWebKey) {
					return MustCreateTokenAndKeys(cfg)
				},
				requestFn: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "Bearer "+token),
					}
				},
			},
			want:                nil,
			wantErrAtUserRegExp: errors.New("oidc: expected audience \"abc\" got \\[\"metal-stack\"\\]"),
		},
		{
			name: "All good",
			args: args{
				tokenCfg: DefaultTokenCfg(),
				issuerConfig: &IssuerConfig{
					Tenant:   "XY",
					Issuer:   "", // will automagically be filled if empty
					ClientID: "metal-stack",
				},
				tokenProvider: func(cfg *TokenCfg) (string, jose.JSONWebKey, jose.JSONWebKey) {
					return MustCreateTokenAndKeys(cfg)
				},
				requestFn: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "Bearer "+token),
					}
				},
			},
			want: func(issuer string) *User {
				return &User{
					Issuer:  issuer,
					Subject: defaultTokenSubject,
					EMail:   defaultTokenEMail,
					Name:    defaultTokenName,
					Groups:  []ResourceAccess{"Tn_k8s-all-all-cadm"},
					Tenant:  "XY",
				}
			},
		},
		{
			name: "Malformed Token",
			args: args{
				tokenCfg: DefaultTokenCfg(),
				issuerConfig: &IssuerConfig{
					Tenant:   "XY",
					Issuer:   "", // will automagically be filled if empty
					ClientID: "metal-stack",
				},
				tokenProvider: func(cfg *TokenCfg) (string, jose.JSONWebKey, jose.JSONWebKey) {
					return MustCreateTokenAndKeys(cfg)
				},
				requestFn: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "Bearer "+token+"cyx"),
					}
				},
			},
			want:                nil,
			wantErrAtUserRegExp: errors.New("oidc: malformed jwt: illegal base64 data at input byte 344"),
		},
		{
			name: "Unsupported SignatureAlgorithm",
			args: args{
				tokenCfg: DefaultTokenCfg(),
				issuerConfig: &IssuerConfig{
					Tenant:   "XY",
					Issuer:   "", // will automagically be filled if empty
					ClientID: "metal-stack",
				},
				tokenProvider: func(cfg *TokenCfg) (string, jose.JSONWebKey, jose.JSONWebKey) {
					cfg.Alg = jose.ES256 // not allowed per default
					return MustCreateTokenAndKeys(cfg)
				},
				requestFn: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "Bearer "+token),
					}
				},
			},
			want:                nil,
			wantErrAtUserRegExp: errors.New("oidc: id token signed with unsupported algorithm, expected \\[\"RS256\" \"RS384\" \"RS512\"\\] got \"ES256\""),
		},
		{
			name: "Test timeout",
			args: args{
				tokenCfg: DefaultTokenCfg(),
				issuerConfig: &IssuerConfig{
					Tenant:   "XY",
					Issuer:   "", // will automagically be filled if empty
					ClientID: "metal-stack",
				},
				tokenProvider: func(cfg *TokenCfg) (string, jose.JSONWebKey, jose.JSONWebKey) {
					return MustCreateTokenAndKeys(cfg)
				},
				requestFn: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "Bearer "+token),
					}
				},
				keyServerOpts: []KeyServerOption{KeyResponseTimeDelay(5 * time.Second)},
			},
			want:                nil,
			wantErrAtUserRegExp: errors.New("failed to verify signature: fetching keys oidc: get keys failed Get \"http:\\/\\/127\\.0\\.0\\.1\\:\\d{5}/keys\": context deadline exceeded \\(Client\\.Timeout exceeded while awaiting headers\\)"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tc := tt.args.tokenCfg
			srv, token, err := GenerateTokenAndKeyServer(tc, tt.args.tokenProvider, tt.args.keyServerOpts...)
			if err != nil {
				t.Fatal(err)
			}

			issuerURL := srv.URL

			ic := tt.args.issuerConfig
			// path issuer if not explicitly set
			if ic.Issuer == "" {
				url := issuerURL
				ic.Issuer = url
			}

			o, err := NewGenericOIDC(ic, Timeout(1*time.Second))
			if err != nil {
				if tt.wantErrAtNew == nil || tt.wantErrAtNew.Error() != err.Error() {
					t.Fatalf("NewGenericOIDC() error = %v, wantErr %v", err, tt.wantErrAtNew)
				}

				// ok
				return
			}

			got, err := o.User(tt.args.requestFn(token))
			if err != nil && tt.wantErrAtUserRegExp == nil {
				t.Fatalf("User() error = %v, wantErr %v", err, tt.wantErrAtUserRegExp)
			}
			if err == nil && tt.wantErrAtUserRegExp != nil {
				t.Fatalf("User() error = %v, wantErr %v", err, tt.wantErrAtUserRegExp)
			}
			if err != nil && tt.wantErrAtUserRegExp != nil && !assert.Regexp(t, regexp.MustCompile(tt.wantErrAtUserRegExp.Error()), err.Error()) {
				t.Fatalf("User() error = %v, wantErr %v", err, tt.wantErrAtUserRegExp)
			}

			var wantUser *User
			if tt.want != nil {
				wantUser = tt.want(issuerURL)
			}

			if !reflect.DeepEqual(got, wantUser) {
				diff := cmp.Diff(wantUser, got)
				t.Errorf("User() got = %v, want %v, diff %s", got, wantUser, diff)
			}
		})
	}
}
