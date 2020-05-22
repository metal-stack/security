package security

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"net/http"
	"net/http/httptest"

	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"time"
)

var (
	authtoken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ2NDEyOGM5LWVlYzctNGIyZC1iZTU2LTY0NGU1NGExNWZjYyJ9.eyJhdWQiOlsidG9rZW4tZm9yZ2UiLCJhdXRoLWdvLWNsaSJdLCJlbWFpbCI6ImFjaGltLmFkbWluQHRlbmFudC5kZSIsImV4cCI6MTU1NzQxMDc5OSwiZmVkZXJhdGVkX2NsYWltcyI6eyJjb25uZWN0b3JfaWQiOiJ0ZW5hbnRfbGRhcF9vcGVubGRhcCIsInVzZXJfaWQiOiJjbj1hY2hpbS5hZG1pbixvdT1QZW9wbGUsZGM9dGVuYW50LGRjPWRlIn0sImdyb3VwcyI6WyJrOHNfa2Fhcy1hZG1pbiIsIms4c19rYWFzLWVkaXQiLCJrOHNfa2Fhcy12aWV3IiwiazhzX2RldmVsb3BtZW50X19jbHVzdGVyLWFkbWluIiwiazhzX3Byb2R1Y3Rpb25fX2NsdXN0ZXItYWRtaW4iLCJrOHNfc3RhZ2luZ19fY2x1c3Rlci1hZG1pbiJdLCJpYXQiOjE1NTczODE5OTksImlzcyI6Imh0dHBzOi8vZGV4LnRlc3QuZmktdHMuaW8vZGV4IiwibmFtZSI6ImFjaGltIiwic3ViIjoiYWNoaW0ifQ.IVpuFWpsN9609d5J54vCQsAlW39rDL2yQl0yXqK2bLUvdoB1SfTtnO5zbHZW-YeH1sl8XpSDDBGZdRevOfcfm-QraiSvo58ZL1zIcJHRidOAKApgVA8TLV6DV-7Eo-2MtAFFpN9Yeiu5c0d_8yz6_KADI8nkfeKJgm4vxN3mUjIekBUMj3DH5nbusl3-JiLAtVdyWhmVAQp7vAPwq2etSUbUoTyQ4aWFOfT2BWumFfE7XBd1D0baXDGXZVIdmlVoovbqdNUezKlMKt8zHdmt7kzO5rtUShQHQOIXzRG7MV2BSA-R0tyjAtvRZyTr58T2xNDQR8bjvKYx6T8-elu7N27AnE2HqBvHf89fV7htlUYC3beq1PT2U0VtOGifLBaEwdwk5SdSRdMv6GcTBpEw0xrxaKcpWWmk3V3RU15RPnnljcg79CkxlsjMhi2BzhWz10JAtoCXxa0nihwmYtXcZiwaD7K1XaicO4kN79IpexgQYoVN4RAP7YIAJ5NPq35TLHOGze23YAbE48hAaS5CcDXHDh61oXBVkRAJFXkGUpzp2pjljPDKAjyVt6HHNrl_ors6fHvUn_9Imo3FNaZpoDlsbUS9rVL63ImLIOhd3kDWlF_nZ7NWCIyXBocZyTiE247VUVBJIx9tvW-D1CRLPvo-FHjPXkTErEE8ygqA5dw"

	dk1 = map[string]interface{}{
		"use": "sig",
		"kty": "RSA",
		"kid": "464128c9-eec7-4b2d-be56-644e54a15fcc",
		"alg": "RS256",
		"n":   "qC2IPIE_zbAa8UwgSkTQnlh2JSiTPoMf7Bc4wPHt0InMhxrr6gID9zYAXh8Q9Mwoyuh9oYxwenRXwnqACKyqmPIwhZKerRRqk1y_sLTQDWndvpSISWrOjcEFAWAuHn0b6BU9L06TrO33MULYfhx-R2ftnl1P6pGdght3yuJzLSvOmXE-s3t0KZ4rQn4GAVQ25e9S06tkmel1huJESG9UhKtcaNFN17NakqpePozmhIK4NUxMX-Os3WPoElhU28OmDyw_PdG8CfygXiCrUvIgNlm85JBtkG-A-OaXMntp_aNEM-7YPqsiEKS0bTUUdHVi4Q1cegYciBedOtoVtVUDIIb2wD96rus-cfzN4gnyHtDRjGcIEZBHX_DJ9ZRC7RtO6KwKnHQ6aKSJbfJrJ840msLfPb2oagD0zCNWZHU_W9ClvEbhIzyvk4TgU9ar5z03YB9tMlICinV5zGjUARdBSH5bVNVtAsxfbx8Y7CkTGicz7-ocrsBJB07HR18HbPZf5TdRY4uPA0f3T4w4_wh6wt5qgXU5DjsAYLWabptRBTFyiI0iYwCBSvTtRaDJgMilZJoUjWWj86-Y__xZzwntcuZhYqB7pBvjkOUdlsQfe6s4r1z0-D5NOyYO63t-QH0QVvEVfdDmjCb7zBvde-ph61og5xNDp80VjX-m40y0x7E",
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
		// now check if the current cached keys is identical to our mocked keysets
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

func TestDex_keyfetcher_robustness(t *testing.T) {
	keysfetched := false
	secondKeySet := false
	wakeupCh := make(chan bool, 1)
	sleepDuration := 0 * time.Second
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		select {
		case <-wakeupCh:
		default:
		}
		w.Header().Add("content-type", "application/json")
		if sleepDuration > 0 {
			select {
			case <-wakeupCh:
				return
			case <-time.After(sleepDuration):
				break
			}
		}
		if secondKeySet {
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
	}))

	// default timeout is 5 secs
	sleepDuration = 10 * time.Second
	dx, err := NewDex(srv.URL)
	require.Error(t, err, "expected error timeout")

	// end sleep
	wakeupCh <- true

	// this time the service responds within timeout
	sleepDuration = 100 * time.Millisecond

	// shorten the http-client-timeout
	var client = &http.Client{
		Timeout: time.Second * 2,
	}
	dx, err = NewDex(srv.URL, Client(client), RefreshInterval(3*time.Second))
	require.NoError(t, err)
	require.True(t, keysfetched, "expected the keys to be fetched")
	// keys are available
	_, err = dx.searchKey(dk1["kid"].(string))
	assert.NoError(t, err)
	_, err = dx.searchKey(dk2["kid"].(string))
	assert.NoError(t, err)
	// this forces an update
	_, err = dx.searchKey(dk3["kid"].(string))
	assert.Error(t, err)

	// end sleep
	wakeupCh <- true

	// the update will fail
	sleepDuration = 5 * time.Second

	// wait for refreshInterval to pass
	time.Sleep(4 * time.Second)

	// cannot fetch keys, after that the cache is empty and has error.
	_, err = dx.fetchKeys()
	require.Error(t, err)

	// end sleep
	wakeupCh <- true

	// key update will succeed
	sleepDuration = 200 * time.Millisecond

	// wait for refreshInterval to pass
	time.Sleep(4 * time.Second)

	t.Log("Testing keys")
	data := [][]map[string]interface{}{firstkeys, secondkeys}
	searchkey := dk3["kid"].(string)
	// the server will return first "firstkeys" and on the second call "secondkeys"
	// only the secondkeys contains "dk3", so the following tests if the dex
	// will be refreshed with new keys if a key is not found in the current cached
	// keyset
	for _, d := range data {
		keys, err := dx.fetchKeys()
		secondKeySet = true
		if err != nil {
			t.Errorf("no keys returned: %v", err)
			return
		}
		// now check if the current cached keys is identical to our mocked keysets
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
				err := json.NewEncoder(w).Encode(secondkeydata)
				if err != nil {
					t.Error(err)
				}
			}))

			// change Name to akim and de-prefix groups - just for this test
			dx, err := NewDex(srv.URL, UserExtractor(func(claims *Claims) (user *User, e error) {
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
					Name:   "akim",
					EMail:  claims.EMail,
					Groups: grps,
					Tenant: tenant,
				}
				return &usr, nil
			}))
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
