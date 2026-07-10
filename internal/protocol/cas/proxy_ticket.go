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
	pgtPrefix         = "mxid:cas:pgt:"
	defaultPGTicketTTL = 2 * time.Hour
	proxyTicketTTL    = 30 * time.Second
)

// ProxyGrantingTicket (PGT) is the reusable ticket a service holds after a
// successful validate carrying a pgtUrl. It mints single-use proxy tickets at
// /proxy. Unlike a service ticket it is NOT consumed on use — it lives until
// its TTL — so it is stored separately from the ServiceTicket store.
type ProxyGrantingTicket struct {
	PGT       string    `json:"pgt"`
	UserID    int64     `json:"user_id"`
	TenantID  int64     `json:"tenant_id"`
	AppID     int64     `json:"app_id"`   // the CAS IdP app that minted it — /proxy under a different app_code is rejected
	Username  string    `json:"username"` // resolved principal, copied onto minted proxy tickets
	PGTURL    string    `json:"pgt_url"`  // the pgtUrl this PGT was delivered to; becomes the proxy-chain entry when it mints a PT
	Proxies   []string  `json:"proxies,omitempty"` // inherited chain (empty when minted from an ST, non-empty when minted from a PT)
	CreatedAt time.Time `json:"created_at"`
}

// CreatePGT mints and stores a proxy-granting ticket. proxies is the inherited
// chain (nil for a PGT born of a service ticket, the PT's chain when born of a
// proxy ticket). ttl<=0 uses the default.
func (s *TicketStore) CreatePGT(ctx context.Context, userID, tenantID, appID int64, username, pgtURL string, proxies []string, ttl int) (*ProxyGrantingTicket, error) {
	random, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("generate pgt: %w", err)
	}
	duration := defaultPGTicketTTL
	if ttl > 0 {
		duration = time.Duration(ttl) * time.Second
	}
	pgt := &ProxyGrantingTicket{
		PGT:       "PGT-" + random,
		UserID:    userID,
		TenantID:  tenantID,
		AppID:     appID,
		Username:  username,
		PGTURL:    pgtURL,
		Proxies:   proxies,
		CreatedAt: time.Now(),
	}
	data, err := json.Marshal(pgt)
	if err != nil {
		return nil, fmt.Errorf("marshal pgt: %w", err)
	}
	if err := s.rdb.Set(ctx, pgtPrefix+pgt.PGT, data, duration).Err(); err != nil {
		return nil, fmt.Errorf("store pgt: %w", err)
	}
	return pgt, nil
}

// GetPGT loads a proxy-granting ticket WITHOUT deleting it (PGTs are reusable).
func (s *TicketStore) GetPGT(ctx context.Context, pgtID string) (*ProxyGrantingTicket, error) {
	data, err := s.rdb.Get(ctx, pgtPrefix+pgtID).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("pgt not found or expired")
		}
		return nil, fmt.Errorf("get pgt: %w", err)
	}
	var pgt ProxyGrantingTicket
	if err := json.Unmarshal(data, &pgt); err != nil {
		return nil, fmt.Errorf("unmarshal pgt: %w", err)
	}
	return &pgt, nil
}

// DeletePGT removes a proxy-granting ticket — used to roll back a PGT whose
// pgtUrl callback failed so it can never mint proxy tickets.
func (s *TicketStore) DeletePGT(ctx context.Context, pgtID string) error {
	return s.rdb.Del(ctx, pgtPrefix+pgtID).Err()
}

// CreateProxyTicket mints a single-use proxy ticket (PT-) for targetService from
// a PGT. The proxy chain prepends the PGT's own pgtUrl (the service now
// proxying) to the PGT's inherited chain, so a proxyValidate of this PT reports
// the full ordered <cas:proxies> list, most-recent proxy first.
func (s *TicketStore) CreateProxyTicket(ctx context.Context, pgt *ProxyGrantingTicket, targetService string) (*ServiceTicket, error) {
	random, err := crypto.GenerateRandomString(24)
	if err != nil {
		return nil, fmt.Errorf("generate pt: %w", err)
	}
	proxies := make([]string, 0, len(pgt.Proxies)+1)
	proxies = append(proxies, pgt.PGTURL)
	proxies = append(proxies, pgt.Proxies...)

	pt := &ServiceTicket{
		Ticket:    "PT-" + random,
		UserID:    pgt.UserID,
		TenantID:  pgt.TenantID,
		Service:   targetService,
		Username:  pgt.Username,
		CreatedAt: time.Now(),
		IsProxy:   true,
		Proxies:   proxies,
	}
	data, err := json.Marshal(pt)
	if err != nil {
		return nil, fmt.Errorf("marshal pt: %w", err)
	}
	// Reuse the service-ticket store + prefix: proxyValidate consumes PTs via the
	// same single-use GETDEL path as STs.
	if err := s.rdb.Set(ctx, ticketPrefix+pt.Ticket, data, proxyTicketTTL).Err(); err != nil {
		return nil, fmt.Errorf("store pt: %w", err)
	}
	return pt, nil
}
