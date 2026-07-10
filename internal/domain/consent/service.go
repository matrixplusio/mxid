package consent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/dberr"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// Service errors.
var (
	ErrNotFound = errors.New("consent not found")
)

// Service owns the user/app consent ledger.
//
// Reads always honor revoked_at — a row whose revoked_at is non-NULL is
// treated as absent. Writes upsert by (tenant, user, app): the same user
// granting the same app a different scope set simply updates scopes
// in place and clears revoked_at.
type Service struct {
	db    *gorm.DB
	idGen *snowflake.Generator
}

// NewService wires a Service.
func NewService(db *gorm.DB, idGen *snowflake.Generator) *Service {
	return &Service{db: db, idGen: idGen}
}

// Get returns the active consent row for (tenant, user, app) or nil when
// none exists. A revoked row is treated as nil.
func (s *Service) Get(ctx context.Context, tenantID, userID, appID int64) (*UserAppConsent, error) {
	var row UserAppConsent
	err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND app_id = ? AND revoked_at IS NULL", tenantID, userID, appID).
		First(&row).Error
	if err != nil {
		if dberr.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get consent: %w", err)
	}
	return &row, nil
}

// HasAll returns true when the user has previously granted the app every
// scope in `requested`. Order-insensitive set membership.
func (s *Service) HasAll(ctx context.Context, tenantID, userID, appID int64, requested []string) (bool, error) {
	row, err := s.Get(ctx, tenantID, userID, appID)
	if err != nil {
		return false, err
	}
	if row == nil {
		return false, nil
	}
	granted := make(map[string]struct{}, len(row.Scopes))
	for _, s := range row.Scopes {
		granted[s] = struct{}{}
	}
	for _, r := range requested {
		if _, ok := granted[r]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// Grant upserts the consent row to contain (at least) every scope in
// `scopes`. Existing scopes are preserved — this method is additive so the
// user only ever sees consent prompts for genuinely new scopes.
func (s *Service) Grant(ctx context.Context, tenantID, userID, appID int64, scopes []string) (*UserAppConsent, error) {
	now := time.Now()
	var row UserAppConsent
	err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND app_id = ?", tenantID, userID, appID).
		First(&row).Error

	// A previously REVOKED consent must NOT resurrect its old scopes: merge from
	// an empty base so re-consent grants only what is asked for now. Without this
	// the additive merge silently restores scopes the user explicitly revoked.
	prior := []string(row.Scopes)
	if row.RevokedAt != nil {
		prior = nil
	}
	mergedScopes := mergeScopeSets(prior, scopes)

	if dberr.IsNotFound(err) {
		row = UserAppConsent{
			ID:        s.idGen.Generate(),
			TenantID:  tenantID,
			UserID:    userID,
			AppID:     appID,
			Scopes:    pq.StringArray(mergedScopes),
			GrantedAt: now,
		}
		if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
			return nil, fmt.Errorf("create consent: %w", err)
		}
		return &row, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get consent for upsert: %w", err)
	}

	row.Scopes = pq.StringArray(mergedScopes)
	row.GrantedAt = now
	row.RevokedAt = nil
	if err := s.db.WithContext(ctx).Save(&row).Error; err != nil {
		return nil, fmt.Errorf("update consent: %w", err)
	}
	return &row, nil
}

// Revoke stamps revoked_at on the row so subsequent /authorize calls
// re-prompt. Idempotent — revoking a non-existent / already-revoked
// consent is a no-op.
func (s *Service) Revoke(ctx context.Context, tenantID, userID, appID int64) error {
	now := time.Now()
	res := s.db.WithContext(ctx).
		Model(&UserAppConsent{}).
		Where("tenant_id = ? AND user_id = ? AND app_id = ? AND revoked_at IS NULL", tenantID, userID, appID).
		Updates(map[string]any{"revoked_at": &now})
	if res.Error != nil {
		return fmt.Errorf("revoke consent: %w", res.Error)
	}
	return nil
}

// ListByUser returns the user's active consents across all apps.
//
// Empty result returns an empty (non-nil) slice so JSON encoders emit `[]`,
// not `null` — frontend iterates without nil-guards.
func (s *Service) ListByUser(ctx context.Context, tenantID, userID int64) ([]*UserAppConsent, error) {
	rows := make([]*UserAppConsent, 0)
	err := s.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ? AND revoked_at IS NULL", tenantID, userID).
		Order("granted_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list consent: %w", err)
	}
	return rows, nil
}

func mergeScopeSets(existing []string, incoming []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	out := make([]string, 0, len(existing)+len(incoming))
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range existing {
		add(s)
	}
	for _, s := range incoming {
		add(s)
	}
	return out
}
