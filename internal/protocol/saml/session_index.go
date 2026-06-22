package saml

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SAMLSessionRef holds the session identifiers needed by IdP-initiated SLO
// to address a specific SAML session at the SP.
type SAMLSessionRef struct {
	SessionIndex string `json:"session_index"`
	NameID       string `json:"name_id"`
	SPEntityID   string `json:"sp_entity_id"`
}

// SessionIndexStore persists a per-user-per-app SAML session reference in
// Redis so the IdP-initiated SLO path (Task L3) can look up the SessionIndex
// and NameID to include in the LogoutRequest it sends to the SP.
//
// A single-active-session model is used: recording a new session overwrites
// the previous one. This is acceptable because SAML SPs typically enforce
// one active session per user anyway, and SLO only needs the most-recent ref.
type SessionIndexStore struct {
	rdb *redis.Client
}

// NewSessionIndexStore returns a SessionIndexStore backed by rdb.
func NewSessionIndexStore(rdb *redis.Client) *SessionIndexStore {
	return &SessionIndexStore{rdb: rdb}
}

func sloKey(userID, appID int64) string {
	return fmt.Sprintf("mxid:saml:slo:%d:%d", userID, appID)
}

// Record stores the SAML session ref for userID+appID, replacing any
// previous entry. ttl should match the SAML assertion lifetime.
func (s *SessionIndexStore) Record(ctx context.Context, userID, appID int64, ref SAMLSessionRef, ttl time.Duration) error {
	b, err := json.Marshal(ref)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, sloKey(userID, appID), b, ttl).Err()
}

// Get returns the stored session ref(s) for userID+appID. Returns nil, nil
// when no entry is found (session expired or never recorded).
func (s *SessionIndexStore) Get(ctx context.Context, userID, appID int64) ([]SAMLSessionRef, error) {
	b, err := s.rdb.Get(ctx, sloKey(userID, appID)).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ref SAMLSessionRef
	if err := json.Unmarshal(b, &ref); err != nil {
		return nil, err
	}
	return []SAMLSessionRef{ref}, nil
}

// Delete removes the session ref for userID+appID. Called on logout.
func (s *SessionIndexStore) Delete(ctx context.Context, userID, appID int64) error {
	return s.rdb.Del(ctx, sloKey(userID, appID)).Err()
}
