package security

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"gopkg.in/square/go-jose.v2"
)

func TestGenericOIDC_User(t *testing.T) {
	type args struct {
		tokenCfg      *TokenCfg
		issuerConfig  *IssuerConfig
		tokenProvider TokenProvider
		requestFn     requestFn
	}
	tests := []struct {
		name          string
		args          args
		want          *User
		wantErrAtNew  error
		wantErrAtUser error
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
			want:          nil,
			wantErrAtUser: errors.New("oidc: expected audience \"abc\" got [\"metal-stack\"]"),
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
			want: &User{
				EMail:  "achim@metal-stack.io",
				Name:   "achim",
				Groups: []ResourceAccess{"Tn_k8s-all-all-cadm"},
				Tenant: "XY",
			},
			wantErrAtNew: nil,
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
			want:          nil,
			wantErrAtUser: errors.New("oidc: malformed jwt: illegal base64 data at input byte 344"),
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
			want:          nil,
			wantErrAtUser: errors.New("oidc: id token signed with unsupported algorithm, expected [\"RS256\" \"RS384\" \"RS512\"] got \"ES256\""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tc := tt.args.tokenCfg
			srv, token, err := GenerateTokenAndKeyServer(tc, tt.args.tokenProvider)
			if err != nil {
				t.Fatal(err)
			}

			ic := tt.args.issuerConfig
			// path issuer if not explicitly set
			if ic.Issuer == "" {
				ic.Issuer = srv.URL
			}

			o, err := NewGenericOIDC(ic)
			if err != nil {
				if tt.wantErrAtNew == nil || tt.wantErrAtNew.Error() != err.Error() {
					t.Fatalf("NewGenericOIDC() error = %v, wantErr %v", err, tt.wantErrAtNew)
					return
				}
			}

			if err == nil {
				got, err := o.User(tt.args.requestFn(token))
				if !reflect.DeepEqual(tt.wantErrAtUser, err) {
					t.Errorf("User() error = %v, wantErr %v", err, tt.wantErrAtUser)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("User() got = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
