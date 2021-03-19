package security

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// MultiIssuerCache provides a UserGetter that is backed by multiple IssuerConfigs
// that are cached for a configurable duration.
type MultiIssuerCache struct {
	userGetterProvider UserGetterProvider
	issuerListProvider IssuerListProvider

	cache          map[string]*Issuer
	cacheLock      sync.RWMutex
	reloadInterval time.Duration

	log logr.Logger
}

// IssuerListProvider returns the list of allowed IssuerConfigs
type IssuerListProvider func() ([]*IssuerConfig, error)

// UserGetterProvider creates UserGetter for the given IssuerConfig
type UserGetterProvider func(ic *IssuerConfig) (UserGetter, error)

// NewMultiIssuerCache creates a new MultiIssuerCache with given options
func NewMultiIssuerCache(ilp IssuerListProvider, ugp UserGetterProvider, opts ...MultiIssuerUserGetterOption) (*MultiIssuerCache, error) {

	issuerCache := &MultiIssuerCache{
		issuerListProvider: ilp,
		userGetterProvider: ugp,
		cache:              make(map[string]*Issuer),
		reloadInterval:     6 * time.Hour,
		log:                logr.DiscardLogger{},
	}

	for _, opt := range opts {
		opt(issuerCache)
	}

	// initial update
	err := issuerCache.updateCache()
	if err != nil {
		issuerCache.log.Error(err, "error updating issuer cache")
	}

	// flush cache periodically
	done := make(chan bool)
	ticker := time.NewTicker(issuerCache.reloadInterval)

	go func() {
		for {
			select {
			case <-done:
				ticker.Stop()
				return
			case <-ticker.C:
				issuerCache.log.Info("updating issuer cache")
				err := issuerCache.updateCache()
				if err != nil {
					issuerCache.log.Error(err, "error updating issuer cache")
				}
			}
		}
	}()

	return issuerCache, nil
}

// Option
type MultiIssuerUserGetterOption func(mic *MultiIssuerCache) *MultiIssuerCache

// IssuerReloadInterval lets the client set the issuer cache duration
func IssuerReloadInterval(duration time.Duration) MultiIssuerUserGetterOption {
	return func(o *MultiIssuerCache) *MultiIssuerCache {
		o.reloadInterval = duration
		return o
	}
}

// Logger sets the given Logger
func Logger(log logr.Logger) MultiIssuerUserGetterOption {
	return func(o *MultiIssuerCache) *MultiIssuerCache {
		o.log = log
		return o
	}
}

func (i *MultiIssuerCache) User(rq *http.Request) (*User, error) {

	claims, err := ParseTokenClaimsUnvalidated(rq)
	if err != nil {
		return nil, err
	}

	issuer := claims.Issuer
	aud := claims.Audience

	var iss *Issuer
	for _, clientID := range aud {

		i.log.Info("lookup issuer", "issuer", issuer, "clientid", clientID)

		iss, err = i.getCachedIssuer(issuer, clientID)
		if err != nil {
			if errors.Is(err, IssuerNotFound{}) {
				continue
			}
			return nil, err
		}
		if iss != nil {
			break
		}
	}

	if iss == nil {
		return nil, IssuerNotFound{}
	}

	i.log.Info("found issuer", "issuer", iss)

	if iss.userGetter == nil {
		var err error
		// lazy init userGetter as this will connect to oidc-endpoint
		iss.ugOnce.Do(func() {
			ug, cerr := i.userGetterProvider(iss.issuerConfig)
			if cerr != nil {
				err = cerr
			} else {
				iss.userGetter = ug
				i.updateCachedIssuer(iss)
			}
		})
		if err != nil {
			// lazy initialization failed
			return nil, err
		}
	}

	return iss.userGetter.User(rq)
}

type Issuer struct {
	issuerConfig *IssuerConfig
	ugOnce       sync.Once
	userGetter   UserGetter
}

func (i *Issuer) String() string {
	return fmt.Sprintf("Iss %s, ug: %T", i.issuerConfig, i.userGetter)
}

type Annotations map[string]string

type IssuerConfig struct {
	Annotations Annotations
	Tenant      string
	Issuer      string
	ClientID    string
}

func (i *IssuerConfig) String() string {
	return fmt.Sprintf("IssCfg tenant: %s, iss: %s, cid: %s, annotations: %v", i.Tenant, i.Issuer, i.ClientID, i.Annotations)
}

// updateCache fetches issuerConfigs, flushes and refills the cache
func (i *MultiIssuerCache) updateCache() error {
	ics, err := i.issuerListProvider()
	if err != nil {
		return err
	}
	i.cacheLock.Lock()
	defer i.cacheLock.Unlock()

	return i.syncCache(ics)
}

// syncCache syncs the cache with the given list of IssuerConfig,
// i.e. no longer present entries for tenant-ids get deleted, new entries get added to the cache
func (i *MultiIssuerCache) syncCache(ics []*IssuerConfig) error {

	// clean map
	i.cache = make(map[string]*Issuer)
	// fill cache
	for _, ic := range ics {
		i.cache[cacheKey(ic.Issuer, ic.ClientID)] = &Issuer{issuerConfig: ic}
	}
	return nil
}

// getCachedIssuer returns the Issuer from cache or error
func (i *MultiIssuerCache) getCachedIssuer(issuer, clientid string) (*Issuer, error) {
	i.cacheLock.Lock()
	defer i.cacheLock.Unlock()
	cacheKey := cacheKey(issuer, clientid)
	value, ok := i.cache[cacheKey]
	if ok {
		return value, nil
	}

	return nil, NewIssuerNotFound()
}

// updateCachedIssuer updates the issuer in the cache
func (i *MultiIssuerCache) updateCachedIssuer(iss *Issuer) {
	i.cacheLock.Lock()
	defer i.cacheLock.Unlock()
	i.cache[cacheKey(iss.issuerConfig.Issuer, iss.issuerConfig.ClientID)] = iss
}

// cacheKey creates a unique cache-key for given combination
func cacheKey(issuer, clientid string) string {
	return clientid + "|" + issuer
}

type IssuerNotFound struct{}

func NewIssuerNotFound() IssuerNotFound {
	return IssuerNotFound{}
}

func (i IssuerNotFound) Error() string {
	return "issuer/clientid not found"
}
