package vtls

import (
	"fmt"
	"sync"
	"time"
)

type BundleCache struct {
	keys *Keys
	ttl  time.Duration

	mu sync.Mutex
	m  map[string]*bundleCacheEntry
}

type bundleCacheEntry struct {
	bundle     *BundleV1
	bundleHash [32]byte // sha256(canonical signing bytes)
	expiresAt  time.Time
}

func NewBundleCache(keys *Keys, ttl time.Duration) *BundleCache {
	return &BundleCache{
		keys: keys,
		ttl:  ttl,
		m:    make(map[string]*bundleCacheEntry),
	}
}

// Get returns a stable bundle (and bundle_hash) for the (domain, origin) pair.
// The bundle is regenerated only when expired.
func (c *BundleCache) Get(domain, origin string, now time.Time) (*BundleV1, [32]byte, error) {
	if c == nil || c.keys == nil {
		return nil, [32]byte{}, fmt.Errorf("nil bundle cache")
	}
	key := domain + "|" + origin

	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.m[key]; ok {
		if now.Before(e.expiresAt) {
			return e.bundle, e.bundleHash, nil
		}
	}

	b, hRaw, err := NewBundleV1(c.keys, domain, origin, now, c.ttl)
	if err != nil {
		return nil, [32]byte{}, err
	}
	var h32 [32]byte
	copy(h32[:], hRaw)

	c.m[key] = &bundleCacheEntry{
		bundle:     b,
		bundleHash: h32,
		expiresAt:  time.Unix(b.ExpiresAt, 0),
	}
	return b, h32, nil
}



