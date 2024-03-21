package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ed25519"

	"github.com/gorilla/mux"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TokenCfg contains the data for filling the token
type TokenCfg struct {
	Alg           jose.SignatureAlgorithm
	KeyBitlength  int
	IssuerUrl     string
	Audience      []string
	ExpiresAt     time.Time
	IssuedAt      time.Time
	Id            string
	Subject       string
	Name          string
	PreferredName string
	Email         string
	Roles         []string
}

const (
	//nolint:gosec
	defaultTokenIssuerURL = "https://oidc.metal-stack.io"
	//nolint:gosec
	defaultTokenSubject  = "AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4"
	defaultTokenClientID = "metal-stack"
	defaultTokenName     = "Achim Admin"
	//nolint:gosec
	defaultTokenEMail         = "achim@metal-stack.io"
	defaultTokenPreferredName = "xyz4711"
)

// DefaultTokenCfg creates a TokenCfg filled with default values
func DefaultTokenCfg() *TokenCfg {
	return &TokenCfg{
		Alg:           jose.RS256,
		KeyBitlength:  0, // use default, i.e. 2048 for RSA
		IssuerUrl:     defaultTokenIssuerURL,
		Audience:      []string{defaultTokenClientID},
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		IssuedAt:      time.Now(),
		Id:            "123",
		Subject:       defaultTokenSubject,
		Name:          defaultTokenName,
		PreferredName: defaultTokenPreferredName,
		Email:         defaultTokenEMail,
		Roles:         []string{"Tn_k8s-all-all-cadm"},
	}
}

// MustCreateTokenAndKeys creates a keyset and token, panics on error
func MustCreateTokenAndKeys(cfg *TokenCfg) (token string, pubKey jose.JSONWebKey, privKey jose.JSONWebKey) {
	token, pubKey, privKey, err := CreateTokenAndKeys(cfg)
	if err != nil {
		panic(err)
	}
	return token, pubKey, privKey
}

// CreateTokenAndKeys creates a keyset and token
func CreateTokenAndKeys(cfg *TokenCfg) (token string, pubKey jose.JSONWebKey, privKey jose.JSONWebKey, err error) {
	pubKey, privKey, err = CreateWebkeyPair(cfg.Alg, "sig", cfg.KeyBitlength)
	if err != nil {
		return "", jose.JSONWebKey{}, jose.JSONWebKey{}, err
	}

	cl := jwt.Claims{
		Issuer:    cfg.IssuerUrl,
		Subject:   cfg.Subject,
		Audience:  cfg.Audience,
		Expiry:    jwt.NewNumericDate(cfg.ExpiresAt),
		NotBefore: jwt.NewNumericDate(cfg.IssuedAt),
		IssuedAt:  jwt.NewNumericDate(cfg.IssuedAt),
		ID:        cfg.Id,
	}

	pcl := GenericOIDCClaims{
		Name:              cfg.Name,
		PreferredUsername: cfg.PreferredName,
		EMail:             cfg.Email,
		Roles:             cfg.Roles,
	}

	signer := MustMakeSigner(cfg.Alg, privKey)

	token, err = CreateToken(signer, cl, pcl)
	if err != nil {
		return "", jose.JSONWebKey{}, jose.JSONWebKey{}, err
	}

	return token, pubKey, privKey, nil
}

// TokenProvider creates the token with the given TokenCfg
type TokenProvider func(cfg *TokenCfg) (string, jose.JSONWebKey, jose.JSONWebKey)

type KeyServerConfig struct {
	keyResponseDelay time.Duration
}

type KeyServerOption func(cfg *KeyServerConfig)

func KeyResponseTimeDelay(delay time.Duration) KeyServerOption {
	return func(cfg *KeyServerConfig) {
		cfg.keyResponseDelay = delay
	}
}

// GenerateTokenAndKeyServer starts keyserver, patches tokenCfg (issuer), generates token.
// This method is intended for test purposes, where you need a server that provides
// '.well-known/openid-configuration' and '/keys' endpoints.
func GenerateTokenAndKeyServer(tc *TokenCfg, tokenProvider TokenProvider, opts ...KeyServerOption) (srv *httptest.Server, token string, err error) {

	cfg := &KeyServerConfig{}
	for _, o := range opts {
		o(cfg)
	}

	var issuer string
	var pubKey jose.JSONWebKey
	mx := mux.NewRouter()

	// start test-http-server, the local address will be the issuer-url for our token
	srv = httptest.NewServer(mx)

	// closure: used by fake-oidc-key-server below
	issuer = srv.URL
	// patch TokenCfg with local issuer
	tc.IssuerUrl = issuer
	// generate token
	token, pubKey, _ = tokenProvider(tc)

	// enable oidc discovery
	mx.HandleFunc("/.well-known/openid-configuration", func(writer http.ResponseWriter, request *http.Request) {
		p := providerJSON{
			Issuer:     issuer,
			JWKSURL:    issuer + "/keys",
			Algorithms: []jose.SignatureAlgorithm{tc.Alg},
		}
		err := json.NewEncoder(writer).Encode(p)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}
	})
	// key-endpoint to obtain public-key for token validation
	mx.HandleFunc("/keys", func(writer http.ResponseWriter, request *http.Request) {
		ks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{pubKey},
		}
		if cfg.keyResponseDelay > 0 {
			time.Sleep(cfg.keyResponseDelay)
		}
		err := json.NewEncoder(writer).Encode(ks)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}
	})

	return srv, token, nil
}

// providerJSON is the response struct for the .well-known/openid-configuration endpoint
type providerJSON struct {
	Issuer      string                    `json:"issuer"`
	AuthURL     string                    `json:"authorization_endpoint"`
	TokenURL    string                    `json:"token_endpoint"`
	JWKSURL     string                    `json:"jwks_uri"`
	UserInfoURL string                    `json:"userinfo_endpoint"`
	Algorithms  []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
}

// CreateToken creates a jwt token with the given claims
func CreateToken(signer jose.Signer, cl interface{}, privateClaims ...interface{}) (string, error) {
	builder := jwt.Signed(signer).Claims(cl)
	for i := range privateClaims {
		builder = builder.Claims(privateClaims[i])
	}
	raw, err := builder.Serialize()
	if err != nil {
		return "", err
	}
	return raw, nil
}

// MustMakeSigner creates a Signer and panics if an error occurs
func MustMakeSigner(alg jose.SignatureAlgorithm, k interface{}) jose.Signer {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, nil)
	if err != nil {
		panic("failed to create signer:" + err.Error())
	}
	return sig
}

// CreateWebkeyPair creates a JSONWebKey-Pair.
// alg is one of jose signature-algorithm constants, e.g. jose.RS256.
// use is "sig" for signature or "enc" for encryption, see https://tools.ietf.org/html/rfc7517#page-6
// Arbitrary keylenBits are not supported for Elliptic Curve Algs, here the Bits must match the Algorithms.
func CreateWebkeyPair(alg jose.SignatureAlgorithm, use string, keylenBits int) (jose.JSONWebKey, jose.JSONWebKey, error) {
	kid := uuid.New().String()

	var publicKey crypto.PrivateKey
	var privateKey crypto.PublicKey
	var err error

	publicKey, privateKey, err = GenerateSigningKey(alg, keylenBits)
	if err != nil {
		return jose.JSONWebKey{}, jose.JSONWebKey{}, err
	}

	salg := string(alg)
	publicWebKey := jose.JSONWebKey{Key: publicKey, KeyID: kid, Algorithm: salg, Use: use}
	privateWebKey := jose.JSONWebKey{Key: privateKey, KeyID: kid, Algorithm: salg, Use: use}

	if privateWebKey.IsPublic() || !publicWebKey.IsPublic() || !privateWebKey.Valid() || !publicWebKey.Valid() {
		log.Fatalf("invalid keys were generated")
	}

	return publicWebKey, privateWebKey, nil
}

// GenerateSigningKey generates a keypair for corresponding SignatureAlgorithm.
func GenerateSigningKey(alg jose.SignatureAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
		keylen := map[jose.SignatureAlgorithm]int{
			jose.ES256: 256,
			jose.ES384: 384,
			jose.ES512: 521, // The NIST P-521 named curve has an order (n) length of 521 bits, this is not a typo.
			jose.EdDSA: 256,
		}
		if bits != 0 && bits != keylen[alg] {
			return nil, nil, fmt.Errorf("invalid elliptic curve key size, this algorithm does not support arbitrary size")
		}
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, fmt.Errorf("invalid key size for RSA key, 2048 or more is required")
		}
	case jose.HS256, jose.HS384, jose.HS512:
		return nil, nil, fmt.Errorf("unsupported algorithm %s for signing key", alg)
	}
	switch alg {
	case jose.ES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	case jose.ES384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	case jose.ES512:
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	case jose.EdDSA:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		return pub, key, err
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, err
	case jose.HS256, jose.HS384, jose.HS512:
		return nil, nil, fmt.Errorf("unsupported algorithm %s for signing key", alg)
	default:
		return nil, nil, fmt.Errorf("unknown algorithm %s for signing key", alg)
	}
}
