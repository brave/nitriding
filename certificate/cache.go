package certificate

import (
	"context"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

type Cache struct {
	sync.RWMutex
	store map[string][]byte
}

func NewCache() *Cache {
	return &Cache{store: make(map[string][]byte)}
}

func (cache *Cache) Put(ctx context.Context, key string, data []byte) error {
	cache.Lock()
	defer cache.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	cache.store[key] = data
	return nil
}

func (cache *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	cache.RLock()
	defer cache.RUnlock()

	// check if context is done
	//  needed for Cache to conform to the autocert.Cache interface in tests
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	cert, exists := cache.store[key]
	if !exists {
		return nil, autocert.ErrCacheMiss
	}
	return cert, nil
}

func (cache *Cache) Delete(ctx context.Context, key string) error {
	cache.Lock()
	defer cache.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	delete(cache.store, key)
	return nil
}

func (cache *Cache) Len() int {
	cache.RLock()
	defer cache.RUnlock()

	return len(cache.store)
}
