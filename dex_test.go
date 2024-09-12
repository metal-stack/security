package security

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	"net/http"
	"net/http/httptest"

	"encoding/json"

	"time"

	"github.com/golang-jwt/jwt/v4"
)

var (
	//nolint:gosec
	authtokenAlgRS256 = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjAxYzAyZDVkLWNhYTAtNDQ1MC1hZDc2LWJmOTUwNDIwYjhiNiJ9.eyJhdWQiOlsiY2xpLWlkMSIsImNsaS1pZDIiXSwiZW1haWwiOiJhY2hpbS5hZG1pbkB0ZW5hbnQuZGUiLCJleHAiOjE1NTc0MTA3OTksImZlZGVyYXRlZF9jbGFpbXMiOnsiY29ubmVjdG9yX2lkIjoidGVuYW50X2xkYXBfb3BlbmxkYXAiLCJ1c2VyX2lkIjoiY249YWNoaW0uYWRtaW4sb3U9UGVvcGxlLGRjPXRlbmFudCxkYz1kZSJ9LCJncm91cHMiOlsiazhzX2thYXMtYWRtaW4iLCJrOHNfa2Fhcy1lZGl0IiwiazhzX2thYXMtdmlldyIsIms4c19kZXZlbG9wbWVudF9fY2x1c3Rlci1hZG1pbiIsIms4c19wcm9kdWN0aW9uX19jbHVzdGVyLWFkbWluIiwiazhzX3N0YWdpbmdfX2NsdXN0ZXItYWRtaW4iXSwiaWF0IjoxNTU3MzgxOTk5LCJpc3MiOiJodHRwczovL2RleC50ZXN0Lm1ldGFsLXN0YWNrLmlvL2RleCIsIm5hbWUiOiJhY2hpbSIsInN1YiI6ImFjaGltIn0.t4IKOoXgH0A0CpiZhpIlUEz416NEC6VV4M73Fp71h0r23naabw4lsRLEsTl1ziYXHio-v98AokvDhO2tu-9YRwR4qGKZe4IBndSpNmQjK2zTyKR7fMMKfy11y_YkuqoRrkPEG_BMR8x6s7kuU8tMm-pYlezzKLC-2Od1d-XTNAtr6XP_JKicl0GYRm7_cP0m-baa5D2yYMxyojo7cujORXzyB5IYtJkA8JUQx6Hm2EktvD6dfiQ9Fc6V_vo63-54xY180vMBbASJA7gjKr3BeP8Q8WIb6LT_V3ERElqkDQe9IaIpMXbJeF9hJQHc7wd1aexpmTBnNAxVEyUq1CqpXpg_SdrS6hR7blz9H1_3NrnoYI9OrH7tQoaFJrGqBiNkbr2lvdrIhl6pmaELiLsAMOmS3ulsVWUqJH3qQQDXfnENHHnYiFVGn4u3Bqs7DLBtitGW-fKIZYZINDqTts0_-fSi3GQlyZ_dN-G1_A9Bt38DrymhkUwXG821Jc69AcqFVpGsY0s-fiCh38BJAqBZL4RxirlqvLtwFctJBcbycXUE6wK2PBbGfAFCN0C6tdUVg9iUiOtXnJzHzg-G2pEG1BSQtHNrWv5VwU-NFtXlnh0LkTdsUD-ExvbVJX1YkVcOfzkQcvKvKU7B35ddPcDnlVTPker-DUGw5d3bSH4SpJk"
	//nolint:gosec
	authtokenAlgNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiY2xpLWlkMSIsImNsaS1pZDIiXSwiZW1haWwiOiJhY2hpbS5hZG1pbkB0ZW5hbnQuZGUiLCJleHAiOjE1NTc0MTA3OTksImZlZGVyYXRlZF9jbGFpbXMiOnsiY29ubmVjdG9yX2lkIjoidGVuYW50X2xkYXBfb3BlbmxkYXAiLCJ1c2VyX2lkIjoiY249YWNoaW0uYWRtaW4sb3U9UGVvcGxlLGRjPXRlbmFudCxkYz1kZSJ9LCJncm91cHMiOlsiazhzX2thYXMtYWRtaW4iLCJrOHNfa2Fhcy1lZGl0IiwiazhzX2thYXMtdmlldyIsIms4c19kZXZlbG9wbWVudF9fY2x1c3Rlci1hZG1pbiIsIms4c19wcm9kdWN0aW9uX19jbHVzdGVyLWFkbWluIiwiazhzX3N0YWdpbmdfX2NsdXN0ZXItYWRtaW4iXSwiaWF0IjoxNTU3MzgxOTk5LCJpc3MiOiJodHRwczovL2RleC50ZXN0Lm1ldGFsLXN0YWNrLmlvL2RleCIsIm5hbWUiOiJhY2hpbSIsInN1YiI6ImFjaGltIn0.e30"
	//nolint:gosec
	authtokenAlgNoneKid = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwgImtpZCI6IjEyMyJ9.eyJhdWQiOlsiY2xpLWlkMSIsImNsaS1pZDIiXSwiZW1haWwiOiJhY2hpbS5hZG1pbkB0ZW5hbnQuZGUiLCJleHAiOjE1NTc0MTA3OTksImZlZGVyYXRlZF9jbGFpbXMiOnsiY29ubmVjdG9yX2lkIjoidGVuYW50X2xkYXBfb3BlbmxkYXAiLCJ1c2VyX2lkIjoiY249YWNoaW0uYWRtaW4sb3U9UGVvcGxlLGRjPXRlbmFudCxkYz1kZSJ9LCJncm91cHMiOlsiazhzX2thYXMtYWRtaW4iLCJrOHNfa2Fhcy1lZGl0IiwiazhzX2thYXMtdmlldyIsIms4c19kZXZlbG9wbWVudF9fY2x1c3Rlci1hZG1pbiIsIms4c19wcm9kdWN0aW9uX19jbHVzdGVyLWFkbWluIiwiazhzX3N0YWdpbmdfX2NsdXN0ZXItYWRtaW4iXSwiaWF0IjoxNTU3MzgxOTk5LCJpc3MiOiJodHRwczovL2RleC50ZXN0Lm1ldGFsLXN0YWNrLmlvL2RleCIsIm5hbWUiOiJhY2hpbSIsInN1YiI6ImFjaGltIn0.e30"
	//nolint:gosec
	authtokenAlgHS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsidGhlQXVkaWVuY2UiXSwiZW1haWwiOiJhY2hpbS5hZG1pbkB0ZW5hbnQuZGUiLCJleHAiOjE1ODc3NTAxNzUsImZlZGVyYXRlZF9jbGFpbXMiOnsiY29ubmVjdG9yX2lkIjoidG50X2xkYXBfb3BlbmxkYXAiLCJ1c2VyX2lkIjoiY249YWNoaW0uYWRtaW4sb3U9UGVvcGxlLGRjPXRlbmFudCxkYz1kZSJ9LCJncm91cHMiOlsiZ3JwYSIsImdycGIiXSwiaWF0IjoxNTg3NzM1Nzc1LCJpc3MiOiJodHRwczovL2RleC50ZXN0Lm1ldGFsLXN0YWNrLmlvL2RleCIsIm5hbWUiOiJhY2hpbSIsInN1YiI6ImFjaGltIn0.Kf-ejz7xW8CoJm40jdx9OFbwJ4SRWKaR8_o72WMTGVU"
	//nolint:gosec
	authtokenAlgHS256Kid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsICJraWQiOiIwMWMwMmQ1ZC1jYWEwLTQ0NTAtYWQ3Ni1iZjk1MDQyMGI4YjYifQ.eyJhdWQiOlsidGhlQXVkaWVuY2UiXSwiZW1haWwiOiJhY2hpbS5hZG1pbkB0ZW5hbnQuZGUiLCJleHAiOjE1ODc3NTMxODYsImZlZGVyYXRlZF9jbGFpbXMiOnsiY29ubmVjdG9yX2lkIjoidG50X2xkYXBfb3BlbmxkYXAiLCJ1c2VyX2lkIjoiY249YWNoaW0uYWRtaW4sb3U9UGVvcGxlLGRjPXRlbmFudCxkYz1kZSJ9LCJncm91cHMiOlsiZ3JwYSIsImdycGIiXSwiaWF0IjoxNTg3NzM4Nzg2LCJpc3MiOiJodHRwczovL2RleC50ZXN0Lm1ldGFsLXN0YWNrLmlvL2RleCIsIm5hbWUiOiJhY2hpbSIsInN1YiI6ImFjaGltIn0.vHRBpA1Jvb6kPLI56xCdIh42or96N5sOHg3cHs-is-o"

	dk1 = map[string]interface{}{
		"use": "sig",
		"kty": "RSA",
		"kid": "01c02d5d-caa0-4450-ad76-bf950420b8b6",
		"alg": "RS256",
		"n":   "zFSDsEpZ-EegnJpYFTmaUVz2OvtCQty1gYFxLECICU2lrFCxoAFnkARjbyuvT68sIbhdSZ981YoY_oVohhLOMZjNV3KUhRPlMaSZsEDfnZLOGjfRzjOLNGwtcfu7uLvSVOhaF1bqNUtQHN1ljEmcHWJbJzPFLOBD5uK5tZ-zT0q8NyDRnIB3yNPppk1OpMgmAvxpXaIjsTUfOaOz4vbG6opWg4wz-cLgtyvA1YMSQ24EVnHPC4b2fJOJf9DXf1qkVNjiY9BqO19afv8pM1cliYu66wN4D_eAXQnhA_8j6AQyNkHusaOG1TCzxyPQDtcQYjNZfhQBxXLZE_JM_XdCSAdtwPcQTsySHQHIxsFG3M90DiuukCc7iusAcmCupY5jXTH70_ZykvvaTqxgjavj5zsSndiCwSicrJSoh4YwhqUsZMKivphhyZIb0VpzWRhTYhlN1snC184caa_kPgyRRZux40RxCjluo9Taftm2MUji4BZ_TovUG2IBsOJdp9OdmKT9zuw_feNUL5o3ImCmP4ifI03I3kCATS-KnvNnILQQXYpwP-6hNEZJAXcBtXUnoqMbOdqOjKjNc8ZIBwINe8WVuCZhH2bZc0RK8kh6EgZupMrxAPmmvzfr8RgfU8LKOkQ6Y41UhE7qCkLWARLgQpaRu5HmE_YrZvodqSmY3fU",
		"e":   "AQAB",
	}
	dk2 = map[string]interface{}{
		"use": "sig",
		"kty": "RSA",
		"kid": "0f3abdf4e05337b02fa0e36291b9147379dbb686",
		"alg": "RS256",
		"n":   "sUGZtErd2hymWcdHcjkm5bNqVlvMEkVxIabEgWUwWW0mWc2g5QHKysXDS6Oi1Oyzumjx-dmbZ6nz3C_bJMqEbIwRSyxGnUDziraUIs8WAp0bGv440llxhmT26UifOF9TL8iUvRAVKDzCv3YttyxmLojls3c-L9P-71Uc2NmskeBe9lwE5E-1SX2lx01fjhVRrp2TeujqeY7VR4sdKPXyECn7-W7nuOUAQt4ziiGX-gNrt--SX2oG_2TLw_Urv8O9epw8VjB9zWXKsmjkCUVxPAdSHdnlyRQf7TAhiygcK11Fl2ABIv_DwP0Ei5sd-E6FPqfzrNVA81L16mFHaZLciQ",
		"e":   "AQAB",
	}
	dk3 = map[string]interface{}{
		"use": "sig",
		"kty": "RSA",
		"kid": "d3519837ce558fa66192a82f925c1169de358d63",
		"alg": "RS256",
		"n":   "qMu9ak2GZVy7mgSG2nqDJAlYBqXCTTbtSTEtAVpYKcCZKRkDY7kWkPrE8rdhuZV0sVN1-5SQivaDtfXSMBBaLpZFbhA0l98fH3ExOpVbdlHNNWd3mSJEcEFc1QGhc755shyFIliOW59JMNzETIF8eq-MXMt8dKxtnUVZWJk8EYOQSxYK7E9cl4HtACIoGHchRrUctIUJBFgSRbKx1u-_Qnf9cnJeSNdXKL8l7bvLtm5UZWPQrUo229pQ687jUKZu-k2Xag3bAsRGJ6ScbWuLBIJdOxNbvnA3XyARxvqIeZAoEFxDn3q6rhyG024MeRhn4Rd_RzeEq2Y0hsa68M7pkw",
		"e":   "AQAB",
	}
	dk123 = map[string]interface{}{
		"use": "sig",
		"kty": "RSA",
		"kid": "123",
		"alg": "RS256",
		"n":   "zFSDsEpZ-EegnJpYFTmaUVz2OvtCQty1gYFxLECICU2lrFCxoAFnkARjbyuvT68sIbhdSZ981YoY_oVohhLOMZjNV3KUhRPlMaSZsEDfnZLOGjfRzjOLNGwtcfu7uLvSVOhaF1bqNUtQHN1ljEmcHWJbJzPFLOBD5uK5tZ-zT0q8NyDRnIB3yNPppk1OpMgmAvxpXaIjsTUfOaOz4vbG6opWg4wz-cLgtyvA1YMSQ24EVnHPC4b2fJOJf9DXf1qkVNjiY9BqO19afv8pM1cliYu66wN4D_eAXQnhA_8j6AQyNkHusaOG1TCzxyPQDtcQYjNZfhQBxXLZE_JM_XdCSAdtwPcQTsySHQHIxsFG3M90DiuukCc7iusAcmCupY5jXTH70_ZykvvaTqxgjavj5zsSndiCwSicrJSoh4YwhqUsZMKivphhyZIb0VpzWRhTYhlN1snC184caa_kPgyRRZux40RxCjluo9Taftm2MUji4BZ_TovUG2IBsOJdp9OdmKT9zuw_feNUL5o3ImCmP4ifI03I3kCATS-KnvNnILQQXYpwP-6hNEZJAXcBtXUnoqMbOdqOjKjNc8ZIBwINe8WVuCZhH2bZc0RK8kh6EgZupMrxAPmmvzfr8RgfU8LKOkQ6Y41UhE7qCkLWARLgQpaRu5HmE_YrZvodqSmY3fU",
		"e":   "AQAB",
	}

	firstkeys = []map[string]interface{}{
		dk1,
		dk2,
	}
	firstkeydata = map[string]interface{}{
		"keys": firstkeys,
	}
	secondkeys = []map[string]interface{}{
		dk1,
		dk2,
		dk3,
		dk123,
	}
	secondkeydata = map[string]interface{}{
		"keys": secondkeys,
	}
)

func TestDex_keyfetcher(t *testing.T) {
	keysfetched := false
	second := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		w.Header().Add("content-type", "application/json")
		if second {
			err := json.NewEncoder(w).Encode(secondkeydata)
			if err != nil {
				t.Error(err)
			}
		} else {
			err := json.NewEncoder(w).Encode(firstkeydata)
			if err != nil {
				t.Error(err)
			}
		}
		keysfetched = true
		second = !second
	}))

	dx, err := NewDex(srv.URL)
	if err != nil {
		t.Errorf("NewDex() error = %v", err)
		return
	}
	if keysfetched == false {
		t.Errorf("the keys were not fetched")
		return
	}
	data := [][]map[string]interface{}{firstkeys, secondkeys}
	searchkey := dk3["kid"].(string)
	// the server will return first "firstkeys" and on the secondcall "secondkeys"
	// only the secondkeys contains "dk3", so the following tests if the dex
	// will be refreshed with new keys if a key is not found in the current cached
	// keyset
	for _, d := range data {
		keys, err := dx.fetchKeys()
		if err != nil {
			t.Errorf("no keys returned: %v", err)
			return
		}
		// now check if the current cached key is identical to our mocked keysets
		// so we can be sure there was a fetch-request
		if keys.Len() != len(d) {
			t.Errorf("the fetched keys are not expected, did you update dex?")
			return
		}

		for it := keys.Keys(context.Background()); it.Next(context.Background()); {
			pair := it.Pair()
			key := pair.Value.(jwk.Key)

			keyID := key.KeyID()
			require.NotEmpty(t, keyID)
		}

		k, err := dx.searchKey(searchkey)
		if err != nil {
			t.Errorf("the key %q could not be retrieved: %v", searchkey, err)
			return
		}

		assert.IsType(t, &rsa.PublicKey{}, k)
		pub := k.(*rsa.PublicKey)
		e, err := base64.RawURLEncoding.DecodeString(dk3["e"].(string))
		require.NoError(t, err)
		ei := new(big.Int).SetBytes(e)
		assert.EqualValues(t, ei.Int64(), pub.E)
		n, err := base64.RawURLEncoding.DecodeString(dk3["n"].(string))
		ni := new(big.Int).SetBytes(n)
		require.NoError(t, err)
		assert.Equal(t, ni.String(), pub.N.String())
	}
}

func TestDex_User(t *testing.T) {
	test := []struct {
		name  string
		opt   Option
		token string
		t     time.Time
		err   string
	}{
		{
			name:  "correct bearer",
			token: authtokenAlgRS256,
			t:     time.Date(2019, time.May, 9, 6, 7, 0, 0, time.UTC),
		},
		{
			name:  "correct bearer - explicit whitelist",
			opt:   AlgorithmsWhitelist([]string{"RS256"}),
			token: authtokenAlgRS256,
			t:     time.Date(2019, time.May, 9, 6, 7, 0, 0, time.UTC),
		},
		{
			name:  "token used before issued",
			token: authtokenAlgRS256,
			t:     time.Date(2019, time.May, 9, 6, 6, 0, 0, time.UTC),
			err:   "token used before issued",
		},
		{
			name:  "token is expired",
			token: authtokenAlgRS256,
			t:     time.Date(2019, time.May, 10, 6, 6, 0, 0, time.UTC),
			err:   "token is expired by 15h59m21s",
		},
		{
			name:  "token invalid default whitelist - signature algorithm 'none' no kid",
			token: authtokenAlgNone,
			t:     time.Date(2019, time.May, 10, 6, 6, 0, 0, time.UTC),
			err:   "invalid token",
		},
		{
			name:  "token invalid default whitelist - signature algorithm 'none' with kid",
			token: authtokenAlgNoneKid,
			t:     time.Date(2019, time.May, 10, 6, 6, 0, 0, time.UTC),
			err:   "invalid token",
		},
		{
			name:  "token invalid default whitelist - signature algorithm 'HS256' no kid",
			token: authtokenAlgHS256,
			t:     time.Date(2019, time.May, 10, 6, 6, 0, 0, time.UTC),
			err:   "invalid token",
		},
		{
			name:  "token invalid default whitelist - signature algorithm 'HS256' with kid",
			token: authtokenAlgHS256Kid,
			t:     time.Date(2019, time.May, 10, 6, 6, 0, 0, time.UTC),
			err:   "invalid token",
		},
		{
			name:  "algorithm not in whitelist 'RS256' - signature algorithm 'HS256' with kid",
			token: authtokenAlgHS256Kid,
			opt:   AlgorithmsWhitelist([]string{"RS256"}),
			t:     time.Date(2019, time.May, 10, 6, 6, 0, 0, time.UTC),
			err:   "invalid token",
		},
		{
			name:  "algorithm not in whitelist - empty whitelist",
			token: authtokenAlgRS256,
			opt:   AlgorithmsWhitelist([]string{}),
			t:     time.Date(2019, time.May, 10, 6, 6, 0, 0, time.UTC),
			err:   "invalid token",
		},
	}
	for _, tt := range test {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			jwt.TimeFunc = func() time.Time {
				return tt.t
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
				err := json.NewEncoder(w).Encode(secondkeydata)
				if err != nil {
					t.Error(err)
				}
			}))

			dx, err := NewDex(srv.URL)
			if err != nil {
				t.Errorf("NewDex() error = %v", err)
				return
			}
			if tt.opt != nil {
				tt.opt(dx)
			}
			rq := httptest.NewRequest(http.MethodGet, srv.URL, nil)
			rq.Header.Add("Authorization", "Bearer "+tt.token)
			usr, err := dx.User(rq)
			if err != nil {
				if tt.err != "" && tt.err == err.Error() {
					return
				}
				t.Errorf("got error '%v' but expected %q", err, tt.err)
				return
			}
			if usr.Name != "achim" {
				t.Errorf("username is %q, but should be 'achim'", usr.Name)
			}
			if usr.Tenant != "tenant" {
				t.Errorf("tenant is %q, but should be 'tenant'", usr.Tenant)
			}
		})
	}
}

func TestDex_UserWithOptions(t *testing.T) {
	test := []struct {
		name string
		t    time.Time
		err  string
	}{
		{
			name: "correct bearer",
			t:    time.Date(2019, time.May, 9, 6, 7, 0, 0, time.UTC),
		},
		{
			name: "token used before issued",
			t:    time.Date(2019, time.May, 9, 6, 6, 0, 0, time.UTC),
			err:  "token used before issued",
		},
		{
			name: "token is expired",
			t:    time.Date(2019, time.May, 10, 6, 6, 0, 0, time.UTC),
			err:  "token is expired by 15h59m21s",
		},
	}
	for _, tt := range test {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			jwt.TimeFunc = func() time.Time {
				return tt.t
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
				err := json.NewEncoder(w).Encode(secondkeydata)
				if err != nil {
					t.Error(err)
				}
			}))

			dx, err := NewDex(srv.URL)
			if err != nil {
				t.Errorf("NewDex() error = %v", err)
				return
			}

			// change Name to akim and de-prefix groups - just for this test
			dx.With(UserExtractor(func(claims *Claims) (user *User, e error) {
				var grps []ResourceAccess
				for _, g := range claims.Groups {
					grps = append(grps, ResourceAccess(strings.TrimPrefix(g, "k8s_")))
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
					Name:    "akim",
					EMail:   claims.EMail,
					Groups:  grps,
					Tenant:  tenant,
				}
				return &usr, nil
			}))

			rq := httptest.NewRequest(http.MethodGet, srv.URL, nil)
			rq.Header.Add("Authorization", "Bearer "+authtokenAlgRS256)
			usr, err := dx.User(rq)
			if err != nil {
				if tt.err != "" && tt.err == err.Error() {
					return
				}
				t.Errorf("got error '%v' but expected %q", err, tt.err)
				return
			}
			if usr.Name != "akim" {
				t.Errorf("username is %q, but should be 'akim'", usr.Name)
			}
			if usr.Tenant != "tenant" {
				t.Errorf("tenant is %q, but should be 'tenant'", usr.Tenant)
			}

			require.Contains(t, usr.Groups, ResourceAccess("kaas-view"))
			require.Contains(t, usr.Groups, ResourceAccess("development__cluster-admin"))
			require.Contains(t, usr.Groups, ResourceAccess("production__cluster-admin"))
			require.Contains(t, usr.Groups, ResourceAccess("staging__cluster-admin"))
		})
	}
}
