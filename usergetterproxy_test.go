package security

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserGetterProxy_IllegalToken(t *testing.T) {
	p := NewUserGetterProxy(DummyUG{u: dummyUser1})
	rq := &http.Request{
		Header: createHeader(AuthzHeaderKey, "bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5ODcxMzYxLTEzMjktNGVhMi1iZDM5LTdlNTRiMzE4MGE2NCJ9.eyJhdWQiOlsibWV0YWwtc3RhY2siXSwiZW1haWwiOiJhY2hpbUBtZXRhbC1zdGFjay5pbyIsImV4cCI6MTYxMzM4NTI5OSwiaWF0IjoxNjEzMzg0OTk5LCJpc3MiOiJodHRwczovL29pZGMubWV0YWwtc3RhY2suaW8iLCJqdGkiOiIxMjMiLCJuYW1lIjoiYWNoaW0iLCJuYmYiOjE2MTMzODQ5OTksInJvbGVzIjpbIlRuX2s4cy1hbGwtYWxsLWNhZG0iXSwic3ViIjoiQUl0T2F3bXd0V3djVDBrNTFCYXlld052dXRySlVxc3ZsNnFzN0E0In0.RyN6KuLqhN82q8YVXjXSIyMRfCdIdhuwlK2gXcPgwbJ590--xw3fAzr3Esxt_m3-VwV-4xvRoD8u1Yl5K6MuGirJt24dKZl_qk0CzV3DUF-3nL5NHJ-NVBBLcrQdF7OGu14XMYciuuT6pFNi930lV-P_OQv3Mqrauai6PaAres-k6LaIHw9iF6FeUO8Otwt4XcQknd9bMn6jsAUftWwacuY71uSXThpGZWIA__byGG1KAcXT85Bxa-NvRLYjndbYUYhIGB5VZDLk6U0q4Ok_QyN4HOX48-trsdtEVRNufQz8Xq4YrPkx-UvEbKIOcmAYUuo4BhjBDkYojg3D5tf7knNzeAooQuwgFX7Q4YI3wSc2gcsZi7T73N_C3qsH0njzY39mN_nwVsIqhZHga2ILszQ3fak7bLU5TDS73nMRtsHyU3JgyJsOQfe-iAtnllLmZQsVF2gnfaj4AEgwCDZmrxF8hCc4Bc5FfKPGmbNfS3qdP-9sPrFfdXRD-aZxPWbI6wpl_TMSHXmIaUYkfGnenpyI8Tll6VnKyL8NOlmxnxW9UQ39zbUPcw3TTgEXk_oay1YqeYeYNmyUvICbm2EAM9EsHBFdeOEuHXiNYkKZKpb_FjGgbEFX_qhxnXUsXgSM6AmyErxPz123RbeQv4X5MDceT3eiFUnZi8q_vzvIgU9Mk"),
	}
	_, err := p.User(rq)
	assert.Equal(t, err, errors.New("error parsing token: illegal base64 data at input byte 684"))
}

func TestUserGetterProxy_User(t *testing.T) {
	type args struct {
		proxy *UserGetterProxy
	}
	tests := []struct {
		name    string
		args    args
		want    *User
		wantErr error
	}{
		{
			name: "none",
			args: args{
				proxy: func() *UserGetterProxy {
					return NewUserGetterProxy(nil)
				}(),
			},
			want: nil,
		},
		{
			name: "only default",
			args: args{
				proxy: func() *UserGetterProxy {
					return NewUserGetterProxy(DummyUG{u: dummyUser1})
				}(),
			},
			want: dummyUser1,
		},
		{
			name: "default and alternative",
			args: args{
				proxy: func() *UserGetterProxy {
					p := NewUserGetterProxy(DummyUG{u: dummyUser1},
						UserGetterProxyMapping("https://oidc.metal.io", "metal", DummyUG{u: dummyUser3}),
						UserGetterProxyMapping("https://oidc.metal-stack.io", "metal-stack", DummyUG{u: dummyUser2}),
						UserGetterProxyMapping("https://some-other-oidc.com", "abc123", DummyUG{u: dummyUser4}))
					return p
				}(),
			},
			want: dummyUser2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			rq := &http.Request{
				Header: createHeader(AuthzHeaderKey, "bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImQ5ODcxMzYxLTEzMjktNGVhMi1iZDM5LTdlNTRiMzE4MGE2NCJ9.eyJhdWQiOlsibWV0YWwtc3RhY2siXSwiZW1haWwiOiJhY2hpbUBtZXRhbC1zdGFjay5pbyIsImV4cCI6MTYxMzM4NTI5OSwiaWF0IjoxNjEzMzg0OTk5LCJpc3MiOiJodHRwczovL29pZGMubWV0YWwtc3RhY2suaW8iLCJqdGkiOiIxMjMiLCJuYW1lIjoiYWNoaW0iLCJuYmYiOjE2MTMzODQ5OTksInJvbGVzIjpbIlRuX2s4cy1hbGwtYWxsLWNhZG0iXSwic3ViIjoiQUl0T2F3bXd0V3djVDBrNTFCYXlld052dXRySlVxc3ZsNnFzN0E0In0.RyN6KuLqhN82q8YVXjXSIyMRfCdIdhuwlK2gXcPgwbJ590--xw3fAzr3Esxt_m3-VwV-4xvRoD8u1Yl5K6MuGirJt24dKZl_qk0CzV3DUF-3nL5NHJ-NVBBLcrQdF7OGu14XMYciuuT6pFNi930lV-P_OQv3Mqrauai6PaAres-k6LaIHw9iF6FeUO8Otwt4XcQknd9bMn6jsAUftWwacuY71uSXThpGZWIA__byGG1KAcXT85Bxa-NvRLYjndbYUYhIGB5VZDLk6U0q4Ok_QyN4HOX48-trsdtEVRNufQz8Xq4YrPkx-UvEbKIOcmAYUuo4BhjBDkYojg3D5tf7knNzeAooQuwgFX7Q4YI3wSc2gcsZi7T73N_C3qsH0njzY39mN_nwVsIqhZHga2ILszQ3fak7bLU5TDS73nMRtsHyU3JgyJsOQfe-iAtnllLmZQsVF2gnfaj4AEgwCDZmrxF8hCc4Bc5FfKPGmbNfS3qdP-9sPrFfdXRD-aZxPWbI6wpl_TMSHXmIaUYkfGnenpyI8Tll6VnKyL8NOlmxnxW9UQ39zbUPcw3TTgEXk_oay1YqeYeYNmyUvICbm2EAM9EsHBFdeOEuHXiNYkKZKpb_FjGgbEFX_qhxnXUsXgSM6AmyErxPz9RbeQv4X5MDceT3eiFUnZi8q_vzvIgU9Mk"),
			}

			gotUser, gotErr := tt.args.proxy.User(rq)

			if !reflect.DeepEqual(tt.wantErr, gotErr) {
				t.Errorf("User() error = %v, wantErr %v", gotErr, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(gotUser, tt.want) {
				t.Errorf("NewUserGetterProxy() = %v, want %v", gotUser, tt.want)
			}
		})
	}
}

type DummyUG struct {
	u *User
}

func (d DummyUG) User(rq *http.Request) (*User, error) {
	return d.u, nil
}

var dummyUser1 = &User{
	Name: "User1",
}

var dummyUser2 = &User{
	Name: "User2",
}

var dummyUser3 = &User{
	Name: "User3",
}

var dummyUser4 = &User{
	Name: "User4",
}
