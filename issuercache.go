package security

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// MultiIssuerCache provides a UserGetter that is backed by multiple IssuerConfigs
// that are cached for a configurable duration.
type MultiIssuerCache struct {
	userGetterProvider UserGetterProvider
	issuerListProvider IssuerListProvider

	cache          map[string]*Issuer
	cacheLock      sync.RWMutex
	reloadInterval time.Duration
	retryInterval  time.Duration
	log            *slog.Logger
}

// IssuerListProvider returns the list of allowed IssuerConfigs
type IssuerListProvider func() ([]*IssuerConfig, error)

// UserGetterProvider creates UserGetter for the given IssuerConfig
type UserGetterProvider func(ic *IssuerConfig) (UserGetter, error)

// NewMultiIssuerCache creates a new MultiIssuerCache with given options
// if log is nil, slog is instantiated
func NewMultiIssuerCache(log *slog.Logger, ilp IssuerListProvider, ugp UserGetterProvider, opts ...MultiIssuerUserGetterOption) (*MultiIssuerCache, error) {
	if log == nil {
		jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{})
		log = slog.New(jsonHandler)
	}

	issuerCache := &MultiIssuerCache{
		issuerListProvider: ilp,
		userGetterProvider: ugp,
		cache:              make(map[string]*Issuer),
		reloadInterval:     30 * time.Minute,
		retryInterval:      30 * time.Second,
		log:                log,
	}

	for _, opt := range opts {
		opt(issuerCache)
	}

	var (
		// flush cache periodically
		done         = make(chan bool)
		isRetrying   bool
		reloadTicker *time.Ticker
	)
	// initial update
	err := issuerCache.updateCache()
	if err != nil {
		issuerCache.log.Error("error updating issuer cache", "error", err)
		isRetrying = true
		reloadTicker = time.NewTicker(issuerCache.retryInterval)
	} else {
		isRetrying = false
		reloadTicker = time.NewTicker(issuerCache.reloadInterval)
	}

	go func() {
		for {
			select {
			case <-done:
				reloadTicker.Stop()
				return

			case <-reloadTicker.C:
				issuerCache.log.Info("updating issuer cache")
				err := issuerCache.updateCache()
				if err != nil {
					issuerCache.log.Error("error updating issuer cache, retrying...", "error", err)
					isRetrying = true
					reloadTicker.Reset(issuerCache.retryInterval)
					continue
				}
				if isRetrying {
					isRetrying = false
					reloadTicker.Reset(issuerCache.reloadInterval)
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

// IssuerRetryInterval lets the client set the issuer cache retry sleep period
func IssuerRetryInterval(duration time.Duration) MultiIssuerUserGetterOption {
	return func(o *MultiIssuerCache) *MultiIssuerCache {
		o.retryInterval = duration
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

		i.log.Debug("lookup issuer", "issuer", issuer, "clientid", clientID)

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

	i.log.Debug("found issuer", "issuer", iss)

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
			// set a new sync.Once because the current one is wasted now and will never ever
			// initialize the issuer. Later invocations will fall through and produce
			// a nil pointer dereference
			iss.ugOnce = sync.Once{}
			i.updateCachedIssuer(iss)

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

	return i.syncCache(ics)
}

// syncCache syncs the cache with the given list of IssuerConfig,
// i.e. no longer present entries for tenant-ids get deleted, new entries get added to the cache
func (i *MultiIssuerCache) syncCache(newIcs []*IssuerConfig) error {

	i.cacheLock.Lock()
	defer i.cacheLock.Unlock()

	// create map for fast tenant lookup by tenant-id and ensure uniqueness
	newTenantIDMap := make(map[string]*IssuerConfig)
	for _, ni := range newIcs {
		_, alreadyThere := newTenantIDMap[ni.Tenant]
		if alreadyThere {
			i.log.Info("syncCache - skipping duplicate in new tenant-list", "tenant", ni.Tenant)
			continue
		}
		newTenantIDMap[ni.Tenant] = ni
	}

	// check if cached tenant-entries must be deleted
	for cidIssKey, v := range i.cache {
		// is cached tenant still in new tenant list?
		tenant := v.issuerConfig.Tenant
		newTenantConfig, found := newTenantIDMap[tenant]
		if !found {
			delete(i.cache, cidIssKey)
			i.log.Info("syncCache - delete tenant from cache", "tenant", tenant, "key", cidIssKey)
			continue
		}

		// update the annotations always
		v.issuerConfig.Annotations = newTenantConfig.Annotations

		// found existing cached tenant, check for update
		newCidIssKey := cacheKey(newTenantConfig.Issuer, newTenantConfig.ClientID)
		if cidIssKey != newCidIssKey {
			// issuer/clientID changed for tenant
			// delete old entry
			delete(i.cache, cidIssKey)
			// add new entry
			i.cache[newCidIssKey] = &Issuer{issuerConfig: newTenantConfig}
			i.log.Info("syncCache - updated tenant in cache", "tenant", tenant, "key", cidIssKey, "annotations", newTenantConfig.Annotations)
		}

		// delete entry from newTenantIDMap, as it is already processed
		delete(newTenantIDMap, tenant)
	}

	// add tenants that are not yet present
	for _, ic := range newTenantIDMap {
		key := cacheKey(ic.Issuer, ic.ClientID)
		i.cache[key] = &Issuer{issuerConfig: ic}
		i.log.Info("syncCache - add tenant to cache", "tenant", ic.Tenant, "key", key, "annotations", ic.Annotations)
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
