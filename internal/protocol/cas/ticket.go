package cas

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/redis/go-redis/v9"
)

const (
	ticketPrefix    = "mxid:cas:ticket:"
	defaultTicketTTL = 30 * time.Second
)

// ServiceTicket represents a CAS service ticket (ST-) or, when IsProxy is set, a
// proxy ticket (PT-). Both are single-use and share the same Redis store; the
// IsProxy flag lets /serviceValidate reject a PT (only /proxyValidate accepts
// one) per the CAS spec.
type ServiceTicket struct {
	Ticket    string   `json:"ticket"`
	UserID    int64    `json:"user_id"`
	TenantID  int64    `json:"tenant_id"`
	Service   string   `json:"service"`
	Username  string   `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	// IsProxy marks this as a proxy ticket (PT-) minted via /proxy from a PGT.
	IsProxy bool `json:"is_proxy,omitempty"`
	// Proxies is the ordered proxy chain surfaced in a proxyValidate response's
	// <cas:proxies> — most-recent proxy first. Empty for a directly-issued ST.
	Proxies []string `json:"proxies,omitempty"`
}

// TicketStore manages CAS service tickets in Redis.
type TicketStore struct {
	rdb *redis.Client
}

// NewTicketStore creates a CAS ticket store.
func NewTicketStore(rdb *redis.Client) *TicketStore {
	return &TicketStore{rdb: rdb}
}

// CreateTicket generates and stores a service ticket (ST-xxx).
func (s *TicketStore) CreateTicket(ctx context.Context, userID, tenantID int64, service, username string, ttl int) (*ServiceTicket, error) {
	random, err := crypto.GenerateRandomString(24)
	if err != nil {
		return nil, fmt.Errorf("generate ticket: %w", err)
	}
	ticket := "ST-" + random

	duration := defaultTicketTTL
	if ttl > 0 {
		duration = time.Duration(ttl) * time.Second
	}

	st := &ServiceTicket{
		Ticket:    ticket,
		UserID:    userID,
		TenantID:  tenantID,
		Service:   service,
		Username:  username,
		CreatedAt: time.Now(),
	}

	data, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	key := ticketPrefix + ticket
	if err := s.rdb.Set(ctx, key, data, duration).Err(); err != nil {
		return nil, fmt.Errorf("store ticket: %w", err)
	}

	return st, nil
}

// ConsumeTicket retrieves and deletes a service ticket (single-use).
func (s *TicketStore) ConsumeTicket(ctx context.Context, ticket string) (*ServiceTicket, error) {
	key := ticketPrefix + ticket
	// GETDEL is atomic: a captured ST can't be validated twice via a
	// Get-then-Del race (both concurrent validations would otherwise read it
	// before either deletes it).
	data, err := s.rdb.GetDel(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("ticket not found or expired")
		}
		return nil, fmt.Errorf("get ticket: %w", err)
	}

	var st ServiceTicket
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("unmarshal ticket: %w", err)
	}

	return &st, nil
}
