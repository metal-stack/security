package security

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

type requestFn func(token string) *http.Request

type userFn func(issuerUrl string) *User

func TestIssuerResolver_User(t *testing.T) {
	type fields struct {
		userExtractorFn GenericUserExtractorFn
		tokenFn         TokenProvider
		clientId        *string
	}
	type args struct {
		rq       requestFn
		tokenCfg *TokenCfg
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantUserFn userFn
		wantErr    error
	}{
		{
			name: "no auth header",
			fields: fields{
				userExtractorFn: DefaultGenericUserExtractor,
			},
			args: args{
				rq: func(token string) *http.Request {
					return &http.Request{
						Header: http.Header{},
					}
				},
			},
			wantUserFn: nil,
			wantErr:    errNoAuthFound,
		},
		{
			name: "no bearer",
			fields: fields{
				userExtractorFn: DefaultGenericUserExtractor,
			},
			args: args{
				rq: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "xyz"),
					}
				},
			},
			wantUserFn: nil,
			wantErr:    errNoAuthFound,
		},
		{
			name: "valid token, expired",
			fields: fields{
				userExtractorFn: DefaultGenericUserExtractor,
				tokenFn:         MustCreateTokenAndKeys,
			},
			args: args{
				rq: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "bearer "+token),
					}
				},
				tokenCfg: func() *TokenCfg {
					c := DefaultTokenCfg()
					exp, err := time.Parse("2006-01-02 15:04:05", "2021-02-03 09:03:41")
					if err != nil {
						panic(err)
					}
					c.ExpiresAt = exp
					return c
				}(),
			},
			wantUserFn: nil,
			wantErr:    errors.New("oidc: token is expired (Token Expiry: 2021-02-03 10:03:41 +0100 CET)"),
		},
		{
			name: "valid token",
			fields: fields{
				userExtractorFn: DefaultGenericUserExtractor,
				tokenFn:         MustCreateTokenAndKeys,
			},
			args: args{
				rq: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "bearer "+token),
					}
				},
			},
			wantUserFn: func(issuerUrl string) *User {
				return &User{
					Name:   "achim",
					EMail:  "achim@metal-stack.io",
					Groups: []ResourceAccess{"Tn_k8s-all-all-cadm"},
					Tenant: "Tn",
				}
			},
			wantErr: nil,
		},
		{
			name: "valid token, multi audience",
			fields: fields{
				userExtractorFn: DefaultGenericUserExtractor,
				tokenFn:         MustCreateTokenAndKeys,
				clientId:        str2p("metal-stack"),
			},
			args: args{
				tokenCfg: func() *TokenCfg {
					cfg := DefaultTokenCfg()
					cfg.Audience = []string{"cloud", "metal", "metal-stack"}
					return cfg
				}(),
				rq: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "bearer "+token),
					}
				},
			},
			wantUserFn: func(issuerUrl string) *User {
				return &User{
					Name:   "achim",
					EMail:  "achim@metal-stack.io",
					Groups: []ResourceAccess{"Tn_k8s-all-all-cadm"},
					Tenant: "Tn",
				}
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var srv *httptest.Server
			var token string
			var err error

			tc := DefaultTokenCfg()
			if tt.args.tokenCfg != nil {
				tc = tt.args.tokenCfg
			}
			issuer := tc.IssuerUrl

			// if a token should be generated, start keyserver to be able to validate the token
			if tt.fields.tokenFn != nil {
				srv, token, err = GenerateTokenAndKeyServer(tc, tt.fields.tokenFn)
				if err != nil {
					t.Fatal(err)
				}
				defer srv.Close()
				issuer = srv.URL
			}

			clientID := tc.Audience[0] // this is ok for our tests as default
			if tt.fields.clientId != nil {
				clientID = *tt.fields.clientId
			}
			ic := &IssuerConfig{
				Tenant:   "Tn",
				Issuer:   issuer,
				ClientID: clientID,
			}

			ir, err := NewMultiIssuerCache(func() ([]*IssuerConfig, error) {
				return []*IssuerConfig{
					ic,
				}, nil
			}, func(ic *IssuerConfig) (UserGetter, error) {
				ug, err := NewGenericOIDC(ic, GenericUserExtractor(DefaultGenericUserExtractor))
				return ug, err
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := ir.User(tt.args.rq(token))
			if !reflect.DeepEqual(tt.wantErr, err) {
				t.Errorf("User() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var wantUser *User
			if tt.wantUserFn != nil {
				wantUser = tt.wantUserFn(issuer)
			}
			if !reflect.DeepEqual(got, wantUser) {
				t.Errorf("User() got = %v, wantUserFn %v", got, wantUser)
			}
		})
	}
}

func str2p(s string) *string {
	return &s
}
