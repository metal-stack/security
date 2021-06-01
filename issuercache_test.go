package security

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/stretchr/testify/require"

	"github.com/google/go-cmp/cmp"
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
					Issuer:  issuerUrl,
					Subject: defaultTokenSubject,
					Name:    defaultTokenPreferredName,
					EMail:   defaultTokenEMail,
					Groups:  []ResourceAccess{"Tn_k8s-all-all-cadm"},
					Tenant:  "Tn",
				}
			},
			wantErr: nil,
		},
		{
			name: "valid token, issuer not found",
			fields: fields{
				userExtractorFn: DefaultGenericUserExtractor,
				tokenFn:         MustCreateTokenAndKeys,
				clientId:        str2p("metal-stack"),
			},
			args: args{
				tokenCfg: func() *TokenCfg {
					cfg := DefaultTokenCfg()
					cfg.Audience = []string{"cloud", "metal"}
					return cfg
				}(),
				rq: func(token string) *http.Request {
					return &http.Request{
						Header: createHeader(AuthzHeaderKey, "bearer "+token),
					}
				},
			},
			wantErr: IssuerNotFound{},
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
					Issuer:  issuerUrl,
					Subject: defaultTokenSubject,
					Name:    defaultTokenPreferredName,
					EMail:   defaultTokenEMail,
					Groups:  []ResourceAccess{"Tn_k8s-all-all-cadm"},
					Tenant:  "Tn",
				}
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		// Ensure we are save for different locations of issuer and enforcing infrastructure
		os.Setenv("TZ", "UTC")
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
				diff := cmp.Diff(wantUser, got)
				t.Errorf("User() got = %v, wantUserFn %v, diff %s", got, wantUser, diff)
			}
		})
	}
}

func str2p(s string) *string {
	return &s
}

func TestMultiIssuerCache_reload(t *testing.T) {
	ugp := func(ic *IssuerConfig) (UserGetter, error) {
		return nil, nil
	}

	calls := 0
	issuerList := []*IssuerConfig{}

	ilp := func() ([]*IssuerConfig, error) {
		calls++
		return issuerList, nil
	}
	ic, err := NewMultiIssuerCache(ilp, ugp, IssuerReloadInterval(1*time.Second))
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	assert.Equal(t, 0, len(ic.cache))

	// prepare list
	issuerList = []*IssuerConfig{
		{
			Annotations: nil,
			Tenant:      "t1",
			Issuer:      "http://issuer/t1",
			ClientID:    "cli-t1",
		},
	}
	// wait for reload
	time.Sleep(2 * time.Second)

	assert.Equal(t, 2, calls)
	assert.Equal(t, 1, len(ic.cache))
}

func TestMultiIssuerCache_syncCache(t *testing.T) {
	type fields struct {
		ilp  IssuerListProvider
		ugp  UserGetterProvider
		opts []MultiIssuerUserGetterOption
	}
	type args struct {
		newIcs []*IssuerConfig
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		want    map[string]*Issuer
	}{
		{
			name: "Update initial existing t1",
			fields: fields{
				ilp: func() ([]*IssuerConfig, error) {
					return []*IssuerConfig{
						{
							Annotations: nil,
							Tenant:      "t1",
							Issuer:      "http://kc.metal-stack/t1",
							ClientID:    "xyz-t1-123",
						},
						{
							Annotations: nil,
							Tenant:      "t2",
							Issuer:      "http://kc.metal-stack/t2",
							ClientID:    "abc-t2-456",
						},
						{
							Annotations: nil,
							Tenant:      "t3",
							Issuer:      "http://kc.metal-stack/t3",
							ClientID:    "abc-t3-456",
						},
						{
							Annotations: nil,
							Tenant:      "t4",
							Issuer:      "http://kc.metal-stack/t4",
							ClientID:    "abc-t4-456",
						},
						{ // duplicate tenants get filtered - but we don't know which of the two
							Annotations: nil,
							Tenant:      "t4",
							Issuer:      "http://kc.metal-stack/t4",
							ClientID:    "abc-t4-456",
						},
					}, nil
				},
				ugp: func(ic *IssuerConfig) (UserGetter, error) {
					return nil, nil
				},
				opts: nil,
			},
			args: args{
				newIcs: []*IssuerConfig{
					{ // updates existing
						Annotations: nil,
						Tenant:      "t1",
						Issuer:      "http://kc.metal-stack/t1x",
						ClientID:    "xyz-t1-123s",
					},
					{ // is unaltered
						Annotations: nil,
						Tenant:      "t2",
						Issuer:      "http://kc.metal-stack/t2",
						ClientID:    "abc-t2-456",
					},
					// t3 is not there anymore, gets deleted
					{ // duplicates get filtered, but we don't know which
						Annotations: nil,
						Tenant:      "t4",
						Issuer:      "http://kc.metal-stack/t4-4711",
						ClientID:    "abc-t4-4711",
					},
					{ // duplicates get filtered, but we don't know which
						Annotations: nil,
						Tenant:      "t4",
						Issuer:      "http://kc.metal-stack/t4-4711",
						ClientID:    "abc-t4-4711",
					},
					{ // this is new
						Annotations: nil,
						Tenant:      "t5",
						Issuer:      "http://kc.metal-stack/t5",
						ClientID:    "abc-t5-456",
					},
				},
			},
			wantErr: false,
			want: map[string]*Issuer{
				"xyz-t1-123s|http://kc.metal-stack/t1x": {
					issuerConfig: &IssuerConfig{
						Tenant:   "t1",
						Issuer:   "http://kc.metal-stack/t1x",
						ClientID: "xyz-t1-123s",
					},
				},
				"abc-t2-456|http://kc.metal-stack/t2": {
					issuerConfig: &IssuerConfig{
						Tenant:   "t2",
						Issuer:   "http://kc.metal-stack/t2",
						ClientID: "abc-t2-456",
					},
				},
				"abc-t4-4711|http://kc.metal-stack/t4-4711": {
					issuerConfig: &IssuerConfig{
						Tenant:   "t4",
						Issuer:   "http://kc.metal-stack/t4-4711",
						ClientID: "abc-t4-4711",
					},
				},
				"abc-t5-456|http://kc.metal-stack/t5": {
					issuerConfig: &IssuerConfig{
						Tenant:   "t5",
						Issuer:   "http://kc.metal-stack/t5",
						ClientID: "abc-t5-456",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {

			i, err := NewMultiIssuerCache(tt.fields.ilp, tt.fields.ugp)
			require.NoError(t, err)
			if err := i.syncCache(tt.args.newIcs); (err != nil) != tt.wantErr {
				t.Errorf("syncCache() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.want != nil {
				diff := cmp.Diff(tt.want, i.cache, cmp.AllowUnexported(Issuer{}), cmpopts.IgnoreFields(Issuer{}, "ugOnce"))
				if diff != "" {
					t.Errorf("cache is = %v, want %v, diff %s", i.cache, tt.want, diff)
				}
			}
		})
	}
}
