package cas

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// CASServiceRef holds the data needed by SLO to send a back-channel
// logout request to a CAS service.
type CASServiceRef struct {
	ServiceURL string `json:"service_url"`
	Ticket     string `json:"ticket"`
}

// ServiceRegistry persists a per-user-per-app set of CAS services that
// a user has authenticated to. Task L5 reads this set to fan-out SLO
// logout requests.
//
// Storage: Redis SET keyed mxid:cas:svc:<userID>:<appID>.
// Each member is a JSON-encoded CASServiceRef. TTL on the set is
// refreshed on every RecordService call (sliding window via the
// last-recorded ticket's TTL).
type ServiceRegistry struct {
	rdb *redis.Client
}

// NewServiceRegistry returns a ServiceRegistry backed by rdb.
func NewServiceRegistry(rdb *redis.Client) *ServiceRegistry {
	return &ServiceRegistry{rdb: rdb}
}

func casServiceKey(userID, appID int64) string {
	return fmt.Sprintf("mxid:cas:svc:%d:%d", userID, appID)
}

// RecordService notes that userID authenticated to serviceURL under ticket for
// the given app. The Redis SET TTL is reset to ttl so the entry ages out
// roughly when the underlying session would have expired.
func (r *ServiceRegistry) RecordService(ctx context.Context, userID, appID int64, serviceURL, ticket string, ttl time.Duration) error {
	ref, err := json.Marshal(CASServiceRef{ServiceURL: serviceURL, Ticket: ticket})
	if err != nil {
		return err
	}
	key := casServiceKey(userID, appID)
	pipe := r.rdb.TxPipeline()
	pipe.SAdd(ctx, key, ref)
	pipe.Expire(ctx, key, ttl)
	_, err = pipe.Exec(ctx)
	return err
}

// ListServices returns all recorded service refs for userID+appID.
// Returns nil, nil when no entry exists.
func (r *ServiceRegistry) ListServices(ctx context.Context, userID, appID int64) ([]CASServiceRef, error) {
	members, err := r.rdb.SMembers(ctx, casServiceKey(userID, appID)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]CASServiceRef, 0, len(members))
	for _, m := range members {
		var ref CASServiceRef
		if json.Unmarshal([]byte(m), &ref) == nil {
			out = append(out, ref)
		}
	}
	return out, nil
}

// Clear removes all service refs for userID+appID. Called on logout (L5).
func (r *ServiceRegistry) Clear(ctx context.Context, userID, appID int64) error {
	return r.rdb.Del(ctx, casServiceKey(userID, appID)).Err()
}
