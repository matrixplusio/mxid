package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Default TTLs for the two-level cache. L1 is short so individual pods
// converge fast on policy changes even without the pub/sub broadcast; L2
// is long enough that ordinary request bursts amortize the DB join cost.
const (
	defaultL1TTL = 60 * time.Second
	defaultL2TTL = 5 * time.Minute
)

// Redis key + channel layout. Kept private so callers cannot construct
// raw keys that bypass the cache invariants.
const (
	cacheKeyPrefix       = "authz:bindings:"
	invalidateChannel    = "authz:invalidate"
	invalidateAllSentinel = "*"
)

// CachedBindingProvider is a write-through, two-level cache for the
// underlying BindingProvider. Reads are answered from L1 (sync.Map +
// per-entry expiry) and L2 (Redis); misses fall back to the inner
// provider and write back to both layers.
//
// Writes (binding/permission/user mutations) MUST call Invalidate so the
// pub/sub broadcast clears every pod's L1 + the shared L2 entry. Bounded-
// TTL fallback prevents stale entries from outliving a missed broadcast
// (network blip, redis restart).
type CachedBindingProvider struct {
	inner BindingProvider
	rdb   *redis.Client

	l1TTL time.Duration
	l2TTL time.Duration

	mu sync.RWMutex
	l1 map[string]l1Entry

	subOnce sync.Once
}

type l1Entry struct {
	bindings []EffectiveBinding
	expireAt time.Time
}

// CacheOptions configures the two-level cache. Zero values fall back to
// the package defaults.
type CacheOptions struct {
	L1TTL time.Duration
	L2TTL time.Duration
}

// NewCachedBindingProvider wraps inner with the two-level cache and
// subscribes to the invalidation channel. The subscription runs for the
// lifetime of the supplied context; cancel it to stop the goroutine.
func NewCachedBindingProvider(ctx context.Context, inner BindingProvider, rdb *redis.Client, opts CacheOptions) *CachedBindingProvider {
	if opts.L1TTL <= 0 {
		opts.L1TTL = defaultL1TTL
	}
	if opts.L2TTL <= 0 {
		opts.L2TTL = defaultL2TTL
	}
	c := &CachedBindingProvider{
		inner: inner,
		rdb:   rdb,
		l1TTL: opts.L1TTL,
		l2TTL: opts.L2TTL,
		l1:    make(map[string]l1Entry),
	}
	if rdb != nil {
		c.startSubscriber(ctx)
	}
	return c
}

// EffectiveBindingsForUser implements BindingProvider with cache lookup
// in front of the wrapped DB-backed provider.
func (c *CachedBindingProvider) EffectiveBindingsForUser(ctx context.Context, tenantID, userID int64) ([]EffectiveBinding, error) {
	key := cacheKey(tenantID, userID)

	if v, ok := c.l1Get(key); ok {
		return v, nil
	}

	if c.rdb != nil {
		if v, ok := c.l2Get(ctx, key); ok {
			c.l1Set(key, v)
			return v, nil
		}
	}

	v, err := c.inner.EffectiveBindingsForUser(ctx, tenantID, userID)
	if err != nil {
		// Fail-closed: don't poison the cache with a stale empty set.
		return nil, err
	}

	c.l1Set(key, v)
	if c.rdb != nil {
		c.l2Set(ctx, key, v)
	}
	return v, nil
}

// Invalidate clears the cache entry for the given (tenant, user) pair on
// every pod listening on the invalidation channel and on the shared L2.
// Call from mutation paths that change the user's effective bindings:
// role_binding write, group membership change, org move, is_super_admin
// flip.
func (c *CachedBindingProvider) Invalidate(ctx context.Context, tenantID, userID int64) error {
	key := cacheKey(tenantID, userID)
	c.l1Delete(key)
	if c.rdb == nil {
		return nil
	}
	if err := c.rdb.Del(ctx, key).Err(); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("authz cache: redis del: %w", err)
	}
	if err := c.rdb.Publish(ctx, invalidateChannel, key).Err(); err != nil {
		return fmt.Errorf("authz cache: redis publish: %w", err)
	}
	return nil
}

// InvalidateAll wipes every cached entry. Use sparingly — meant for
// "role permission changed, every user holding that role is affected"
// when the caller does not want to enumerate them. Broadcasts a sentinel
// so other pods clear their L1 too.
func (c *CachedBindingProvider) InvalidateAll(ctx context.Context) error {
	c.l1Clear()
	if c.rdb == nil {
		return nil
	}
	// Don't scan-and-delete the L2 entries here — that's an O(N) blocking
	// call on the redis box. The TTL is short enough (5 min default) that
	// letting them age out is acceptable.
	if err := c.rdb.Publish(ctx, invalidateChannel, invalidateAllSentinel).Err(); err != nil {
		return fmt.Errorf("authz cache: redis publish: %w", err)
	}
	return nil
}

// --- L1 helpers ----------------------------------------------------------

func (c *CachedBindingProvider) l1Get(key string) ([]EffectiveBinding, bool) {
	c.mu.RLock()
	e, ok := c.l1[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expireAt) {
		return nil, false
	}
	return e.bindings, true
}

func (c *CachedBindingProvider) l1Set(key string, bindings []EffectiveBinding) {
	c.mu.Lock()
	c.l1[key] = l1Entry{bindings: bindings, expireAt: time.Now().Add(c.l1TTL)}
	c.mu.Unlock()
}

func (c *CachedBindingProvider) l1Delete(key string) {
	c.mu.Lock()
	delete(c.l1, key)
	c.mu.Unlock()
}

func (c *CachedBindingProvider) l1Clear() {
	c.mu.Lock()
	c.l1 = make(map[string]l1Entry)
	c.mu.Unlock()
}

// --- L2 helpers ----------------------------------------------------------

// serializedBinding is the wire shape for redis storage. EffectiveBinding
// holds map[string]struct{} which json/encoding cannot round-trip with
// the empty struct value, so we marshal to []string instead.
type serializedBinding struct {
	RoleID      int64    `json:"role_id"`
	Permissions []string `json:"perms"`
	Source      string   `json:"src"`
	SourceID    int64    `json:"src_id"`
	ScopeType   string   `json:"scope_type,omitempty"`
	ScopeID     int64    `json:"scope_id,omitempty"`
	ExpiresAt   *int64   `json:"expires_at,omitempty"` // unix seconds; nil = permanent
}

func (c *CachedBindingProvider) l2Get(ctx context.Context, key string) ([]EffectiveBinding, bool) {
	raw, err := c.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return nil, false
	}
	var serialized []serializedBinding
	if err := json.Unmarshal(raw, &serialized); err != nil {
		return nil, false
	}
	out := make([]EffectiveBinding, len(serialized))
	for i, s := range serialized {
		perms := make(map[string]struct{}, len(s.Permissions))
		for _, p := range s.Permissions {
			perms[p] = struct{}{}
		}
		eb := EffectiveBinding{
			RoleID:      s.RoleID,
			Permissions: perms,
			Source:      s.Source,
			SourceID:    s.SourceID,
			ScopeType:   ScopeKind(s.ScopeType),
			ScopeID:     s.ScopeID,
		}
		if s.ExpiresAt != nil {
			t := time.Unix(*s.ExpiresAt, 0)
			eb.ExpiresAt = &t
		}
		out[i] = eb
	}
	return out, true
}

func (c *CachedBindingProvider) l2Set(ctx context.Context, key string, bindings []EffectiveBinding) {
	serialized := make([]serializedBinding, len(bindings))
	for i, b := range bindings {
		perms := make([]string, 0, len(b.Permissions))
		for p := range b.Permissions {
			perms = append(perms, p)
		}
		sb := serializedBinding{
			RoleID:      b.RoleID,
			Permissions: perms,
			Source:      b.Source,
			SourceID:    b.SourceID,
			ScopeType:   string(b.ScopeType),
			ScopeID:     b.ScopeID,
		}
		if b.ExpiresAt != nil {
			unix := b.ExpiresAt.Unix()
			sb.ExpiresAt = &unix
		}
		serialized[i] = sb
	}
	raw, err := json.Marshal(serialized)
	if err != nil {
		return
	}
	// Don't propagate Set errors — cache best-effort, do not break the
	// permission check flow if redis is momentarily unhealthy.
	_ = c.rdb.Set(ctx, key, raw, c.l2TTL).Err()
}

// --- pub/sub -------------------------------------------------------------

func (c *CachedBindingProvider) startSubscriber(ctx context.Context) {
	c.subOnce.Do(func() {
		sub := c.rdb.Subscribe(ctx, invalidateChannel)
		ch := sub.Channel()
		go func() {
			defer sub.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case msg, ok := <-ch:
					if !ok {
						return
					}
					if msg.Payload == invalidateAllSentinel {
						c.l1Clear()
						continue
					}
					c.l1Delete(msg.Payload)
				}
			}
		}()
	})
}

func cacheKey(tenantID, userID int64) string {
	return fmt.Sprintf("%s%d:%d", cacheKeyPrefix, tenantID, userID)
}
