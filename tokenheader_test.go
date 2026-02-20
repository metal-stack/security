package security

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-jose/go-jose/v4/jwt"
)

func createHeader(key, value string) http.Header {
	h := http.Header{}
	h.Add(key, value)
	return h
}

func Test_ExtractBearer(t *testing.T) {
	tests := []struct {
		name    string
		rq      *http.Request
		want    string
		wantErr bool
	}{
		{
			name: "No Authorization Header",
			rq: &http.Request{
				Header: createHeader("abc", "def"),
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Authorization Header but no Bearer",
			rq: &http.Request{
				Header: createHeader("Authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l"),
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Authorization Header, Bearer empty",
			rq: &http.Request{
				Header: createHeader("Authorization", "Bearer"),
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Authorization Header, Bearer",
			rq: &http.Request{
				Header: createHeader("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr: false,
		},
		{
			name: "Authorization Header, Bearer lowercase",
			rq: &http.Request{
				Header: createHeader("Authorization", "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr: false,
		},
		{
			name: "Authorization Header, Bearer uppercase",
			rq: &http.Request{
				Header: createHeader("Authorization", "BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
			},
			want:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractBearer(tt.rq)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractBearer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractBearer() got = %v, want %v", got, tt.want)
			}
		})
	}
}

var testCfg = DefaultTokenCfg()
var testToken, _, _ = MustCreateTokenAndKeys(testCfg)

func Test_ParseTokenClaimsUnvalidated(t *testing.T) {
	tests := []struct {
		name    string
		rq      *http.Request
		want    *jwt.Claims
		wantErr bool
	}{
		{
			name: "No Authorization Header",
			rq: &http.Request{
				Header: createHeader("abc", "def"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Authorization Header but no Bearer",
			rq: &http.Request{
				Header: createHeader("Authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Authorization Header, Bearer empty",
			rq: &http.Request{
				Header: createHeader("Authorization", "Bearer"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "peek token",
			rq: &http.Request{
				Header: createHeader("Authorization", "Bearer "+testToken),
			},
			want: &jwt.Claims{
				Issuer:    testCfg.IssuerUrl,
				Subject:   testCfg.Subject,
				Audience:  testCfg.Audience,
				Expiry:    jwt.NewNumericDate(testCfg.ExpiresAt),
				NotBefore: jwt.NewNumericDate(testCfg.IssuedAt),
				IssuedAt:  jwt.NewNumericDate(testCfg.IssuedAt),
				ID:        testCfg.Id,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTokenClaimsUnvalidated(tt.rq)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTokenClaimsUnvalidated() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				diff := cmp.Diff(got, tt.want)
				t.Errorf("ParseTokenClaimsUnvalidated() got = %v, want %v\n%s", got, tt.want, diff)
			}
		})
	}
}
