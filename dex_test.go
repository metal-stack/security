package security

import (
	"testing"

	"net/http"
	"net/http/httptest"

	"encoding/json"

	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	authtoken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0Yzc0ZWRlOGJmYWU2Mzg2NWM1Nzc0NWRkNGMyYzkxMDY0Mjc1ZTkifQ.eyJpc3MiOiJodHRwczovL2RleC50ZXN0LmZpLXRzLmlvL2RleCIsInN1YiI6IkNpaGpiajFoWTJocGJTNWhaRzFwYml4dmRUMVFaVzl3YkdVc1pHTTlaaTFwTFhSekxHUmpQV1JsRWdsc1pHRndYMlpwZEhNIiwiYXVkIjpbInRva2VuLWZvcmdlIiwiYXV0aC1nby1jbGkiXSwiZXhwIjoxNTU3NDEwNzk5LCJpYXQiOjE1NTczODE5OTksImF6cCI6ImF1dGgtZ28tY2xpIiwiYXRfaGFzaCI6InFaOTQ2bm5GNF92S3NoUV9iejBMWXciLCJlbWFpbCI6ImFjaGltLmFkbWluQGYtaS10cy5kZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsiazhzX2thYXMtYWRtaW4iLCJrOHNfa2Fhcy1lZGl0IiwiazhzX2thYXMtdmlldyIsIms4c19kZXZlbG9wbWVudF9fY2x1c3Rlci1hZG1pbiIsIms4c19wcm9kdWN0aW9uX19jbHVzdGVyLWFkbWluIiwiazhzX3N0YWdpbmdfX2NsdXN0ZXItYWRtaW4iXSwibmFtZSI6ImFjaGltIiwiZmVkZXJhdGVkX2NsYWltcyI6eyJjb25uZWN0b3JfaWQiOiJsZGFwX2ZpdHMiLCJ1c2VyX2lkIjoiY249YWNoaW0uYWRtaW4sb3U9UGVvcGxlLGRjPWYtaS10cyxkYz1kZSJ9fQ.nhEPRpjGVpxvcXHInicoBF0ECPWZHjKMnqUSvLJoOC8fK04ZXepUX7YbW_Nas0r2YAdu1iQkv91FLJ0qUEX03m3cvxOABHQ-LdBEB0BUxkmU8IuCOysPqG__zxdAAGCgSBvl4R0IJJYoDMG1uyDKAi6AWhGU-B58LaQnbhvwT5w6g_st5UXw-_HRgaqbhplcUSxFdoLEOnl-Cn4HhBza7VLcygMn30Pk4Acvsuy38z1JcmvuV11is9dHspkIlxdW_gNFhOMd-61zpjMqDhvzh369uppx4w4I60byC8eY392oxOnwC1bJPMvgj5gSDwzqU9VRW7C1gIJFs_c52W9PSg"
	validtime = "2019-05-09T06:07:00Z"

	dk1 = map[string]interface{}{
		"use": "sig",
		"kty": "RSA",
		"kid": "f4c74ede8bfae63865c57745dd4c2c91064275e9",
		"alg": "RS256",
		"n":   "smjpdBVie2pYdaupCqQikXtj99Tlv6LjK7Sb-fOdLLU7bBuQGJUpJxdma6jPs1Bsd-bEaepknqSucZkYIzjnJ8BSdDDW8l_m6DUoQpzuyJVukN7RDsUH9wn-VsF_OeXdfrQd5Y-_aU2ht8dJNiZpfiFYsayfn_7bAs1V58JKVeNMvz0qmVoYk6gz7kKUBx0kxZY4nANkPr4t7CROcwWRJlR8jRQr5t8ZhQGwtr1a658_SxiyyPjbPUTuTObFjb2629KTbFBfV97ltvg0XSYe67W7b_gYXdA0iaIohpYy1sFTGVge-mxjyqG01e7nTBMYMmyo87KkAdItmJ3WRJi7JQ",
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
			json.NewEncoder(w).Encode(secondkeydata)
		} else {
			json.NewEncoder(w).Encode(firstkeydata)
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
		// now check fi the current cached keys is identical to our mocked keysets
		// so we can be sure there was a fetch-request
		if len(keys.Keys) != len(d) {
			t.Errorf("the fetched keys are not expected, did you update dex?")
			return
		}
		for i, k := range keys.Keys {
			kid := d[i]["kid"].(string)
			if k.KeyID() != kid {
				t.Errorf("got KeyID: %q, want %q", k.KeyID(), kid)
			}
		}
		_, err = dx.searchKey(searchkey)
		if err != nil {
			t.Errorf("the key %q could not be retrieved: %v", searchkey, err)
			return
		}
	}
}

func TestDex_User(t *testing.T) {
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
			err:  "Token used before issued",
		},
		{
			name: "token is expired",
			t:    time.Date(2019, time.May, 10, 6, 6, 0, 0, time.UTC),
			err:  "token is expired by 15h59m21s",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			jwt.TimeFunc = func() time.Time {
				return tt.t
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
				json.NewEncoder(w).Encode(secondkeydata)
			}))

			dx, err := NewDex(srv.URL)
			if err != nil {
				t.Errorf("NewDex() error = %v", err)
				return
			}
			rq := httptest.NewRequest(http.MethodGet, srv.URL, nil)
			rq.Header.Add("Authorization", "Bearer "+authtoken)
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
		})
	}
}
