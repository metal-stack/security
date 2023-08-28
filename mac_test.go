package security

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	randByteString = func(n int) []byte {
		return []byte{1, 2, 3, 4, 5, 6}
	}
	flag.Parse()
	os.Exit(m.Run())
}

func TestAddAuth(t *testing.T) {
	// Use the authtype 'mytype' and the shared key (1,2,3)
	hm := NewHMACAuth("mytype", []byte{1, 2, 3})
	rq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/myurl", nil)
	ts := time.Date(2019, time.January, 16, 14, 44, 45, 123, time.UTC)
	// now add a HMCA with the given date and the body {4,5,6}
	hm.AddAuth(rq, ts, []byte{4, 5, 6})
	auth := rq.Header.Get("Authorization")
	want := "mytype f8d293a06bdde899a5bd1dd61b13842564650c717c742db02c4e1a888fc22501"
	if auth != want {
		t.Errorf("got wrong auth header: want %q, got %q", want, auth)
	}
}

func ExampleHMACAuth() {
	u := User{Name: "Bicycle Repair Man"}

	// Use the authtype 'mytype' and the shared key (1,2,3)
	// we also connect a user and set a lifetime

	hm := NewHMACAuth(
		"mytype",
		[]byte{1, 2, 3},
		WithUser(u),
		WithLifetime(10*time.Second))

	fmt.Println(hm.AuthUser.Name)
	fmt.Println(hm.Lifetime)
	fmt.Println(hm.Type)
	// the key is not accessible
	fmt.Println(hm.key)
	// Output:
	// Bicycle Repair Man
	// 10s
	// mytype
	// [1 2 3]
}

func ExampleHMACAuth_User() {
	u := User{Name: "Bicycle Repair Man"}

	// Use the authtype 'mytype' and the shared key (1,2,3)
	// we also set the lifetime to zero so the test will work here
	// never do this in production.
	hm := NewHMACAuth(
		"mytype",
		[]byte{1, 2, 3},
		WithUser(u),
		WithLifetime(0))

	mybody := []byte{4, 5, 6}
	rq := httptest.NewRequest(http.MethodGet, "/myurl", bytes.NewReader(mybody))
	t := time.Date(2019, time.January, 16, 14, 44, 45, 123, time.UTC)

	// now add a HMCA with the given date and the body {4,5,6}
	hm.AddAuth(rq, t, mybody)

	usr, _ := hm.User(rq)
	fmt.Println(usr.Name)
	// Output:
	// Bicycle Repair Man
}

func ExampleWithUser() {
	u := User{Name: "Bicycle Repair Man"}
	hm := NewHMACAuth("mytype", []byte{1, 2, 3}, WithUser(u))
	fmt.Println(hm.AuthUser.Name)
	// Output: Bicycle Repair Man
}

func ExampleWithLifetime() {
	hm := NewHMACAuth("mytype", []byte{1, 2, 3}, WithLifetime(10*time.Second))
	fmt.Println(hm.Lifetime)
	// Output: 10s
}

func TestHMACAuth_User(t *testing.T) {
	tm := time.Date(2019, time.January, 16, 14, 44, 45, 123, time.UTC)
	authtype := "mytype"
	u := User{Name: "Bicycle Repair Man"}
	mybody := []byte{4, 5, 6}

	testdata := []struct {
		name     string
		auth     string
		ts       string
		lifetime time.Duration
		err      error
		errcheck func(*testing.T, error)
	}{
		{
			name: "empty authorization",
			auth: "",
			err:  errNoAuthFound,
		},
		{
			name: "illegal authorization header",
			auth: "abc",
			err:  errIllegalAuthFound,
		},
		{
			name: "wrong hmac",
			auth: authtype + " 1234567",
			ts:   tm.Format(time.RFC3339),
			errcheck: func(t *testing.T, e error) {
				//nolint:errorlint
				_, ok := e.(*WrongHMAC)
				if !ok {
					t.Fatalf("the error is not a wrong hmac")
				}
			},
		},
		{
			name: "correct usage",
			auth: "<calc>",
			err:  nil,
		},
		{
			name: "wrong timestamp",
			auth: "<calc>",
			ts:   time.Now().String(),
			errcheck: func(t *testing.T, e error) {
				if e == nil {
					t.Fatalf("a wrong timestamp should fail")
					return
				}
				if !strings.Contains(e.Error(), "unknown timestamp") {
					t.Fatalf("the error %q is unexpected", e)
				}
			},
		},
		{
			name:     "too old",
			auth:     "<calc>",
			ts:       time.Now().Add(-20 * time.Second).Format(time.RFC3339),
			lifetime: 10 * time.Second,
			errcheck: func(t *testing.T, e error) {
				if e == nil {
					t.Fatalf("an old date should fail")
					return
				}
				if !strings.Contains(e.Error(), "too old") {
					t.Fatalf("the error %q is unexpected", e)
				}
			},
		},
	}

	for _, st := range testdata {
		st := st
		t.Run(st.name, func(t *testing.T) {
			hm := NewHMACAuth(
				authtype,
				[]byte{1, 2, 3},
				WithUser(u),
				WithLifetime(st.lifetime))
			rq := httptest.NewRequest(http.MethodGet, "/myurl", bytes.NewReader(mybody))
			if st.auth == "<calc>" {
				hm.AddAuth(rq, tm, mybody)
			} else if st.auth != "" {
				rq.Header.Add("Authorization", st.auth)
			}
			if st.ts != "" {
				rq.Header.Set(TsHeaderKey, st.ts)
			}
			_, err := hm.User(rq)
			if st.errcheck != nil {
				st.errcheck(t, err)
				return
			}
			if !errors.Is(st.err, err) {
				t.Fatalf("the error %q is unexpected, we wanted: %q", err, st.err)
			}

		})
	}
}

func TestMacCalc(t *testing.T) {
	u := User{Name: "Bicycle Repair Man"}
	hm := NewHMACAuth("mytype", []byte{1, 2, 3}, WithUser(u))
	mac, ts := hm.create(time.Date(2019, time.January, 16, 14, 44, 45, 123, time.UTC), []byte{6, 7, 8, 9})
	expectmac := "bfb747058c7036befe1e32ce1d180099aa85951656e2164245b53e766074e262" // nolint:gosec
	expectts := "2019-01-16T14:44:45Z"
	if mac != expectmac {
		t.Fatalf("expected mac %q, but got %q", expectmac, mac)
	}
	if ts != expectts {
		t.Fatalf("expected ts %q, but got %q", expectts, ts)
	}
}

func TestMacCalc2(t *testing.T) {
	testdata := []struct {
		name     string
		user     string
		hmac     string
		date     string
		data     []string
		expected string
	}{
		{
			name:     "test admin",
			user:     "Metal-Admin",
			hmac:     "metal-test-admin",
			date:     "2019-05-29T09:26:39.000Z",
			data:     []string{"GET", ""},
			expected: "dd864d767ca9eec0337727e6ae69a30c47fa1501d1df9c7f2c4caaa83cf2f9f3",
		},
		{
			name:     "test viewer",
			user:     "Metal-Viewer",
			hmac:     "metal-test-view",
			date:     "2019-05-29T09:26:39.000Z",
			data:     []string{"GET", ""},
			expected: "fa7874b573da17b6b3d16d0f93eb294487cc6dba4f7c62fcac66016ad9601780",
		},
		{
			name:     "test viewer",
			user:     "Metal-Viewer",
			hmac:     "metal-test-admin",
			date:     "2019-05-29T12:10:28.000Z",
			data:     []string{"GET", ""},
			expected: "086fe2ca42719ce22e5c4d4f90ab7c3ec18bb7c43827adeff2a9f19105c1b8c7",
		},
		{
			name:     "test admin",
			user:     "Metal-Admin",
			hmac:     "metal-test-admin",
			date:     "2019-05-29T10:43:44.000Z",
			data:     []string{"POST", "{\"description\":\"Ubuntu 18.04 Minimal\",\"features\":[\"machine\"],\"id\":\"ubuntu-18.04\",\"name\":\"Ubuntu 18.04\",\"url\":\"http://192.168.2.1:9000/metal/images/os/ubuntu/18.04/img.tar.lz4\"}\n"},
			expected: "7774b8abfcdb56d2e17ff0f78dceae62bd61e2cc785ba59c2017a04c4944e615",
		},
		{
			name:     "test admin",
			user:     "Metal-Admin",
			hmac:     "metal-test-admin",
			date:     "2019-05-29T12:30:43Z",
			data:     []string{"PUT", ""},
			expected: "e4b6f0e0f793e58efe7121fc5a3fe731f593e40f3ac27ebc1af09366ef7415f5",
		},
	}
	for _, td := range testdata {
		td := td
		t.Run(td.name, func(t *testing.T) {
			u := User{Name: td.user}
			hm := NewHMACAuth(td.user, []byte(td.hmac), WithUser(u))
			dt, _ := time.Parse(time.RFC3339, td.date)
			var data [][]byte
			for _, d := range td.data {
				data = append(data, []byte(d))
			}
			mac, _ := hm.create(dt, data...)
			if mac != td.expected {
				t.Fatalf("expected mac %q, but got %q", td.expected, mac)
			}
		})
	}
}

func Test_randomByteString(t *testing.T) {
	// make sure that we dont rely on pseudo-random-numbers
	require.NotEqual(t, "XVlBzgbaiCMRAjWwhTHctcuA", string(randomByteString(24)))
}
