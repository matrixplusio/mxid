package user

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A backup code is single-use: the second MarkUsed on an already-consumed code
// must be rejected, not silently succeed. Before the RowsAffected check, a race
// (two logins presenting the same code) could consume it twice.
func TestBackupCodeRepo_MarkUsedIsSingleUse(t *testing.T) {
	db := newChildGuardDB(t) // AutoMigrates MFABackupCode
	repo := NewBackupCodeRepository(db)
	ctx := context.Background()

	code := &MFABackupCode{ID: 42, UserID: 7, CodeHash: "hash", CreatedAt: time.Now()}
	if err := db.Create(code).Error; err != nil {
		t.Fatalf("seed code: %v", err)
	}

	if err := repo.MarkUsed(ctx, 42, time.Now()); err != nil {
		t.Fatalf("first MarkUsed should succeed: %v", err)
	}
	if err := repo.MarkUsed(ctx, 42, time.Now()); !errors.Is(err, ErrMFAInvalidCode) {
		t.Fatalf("second MarkUsed must be rejected as invalid (single-use); got %v", err)
	}
}
