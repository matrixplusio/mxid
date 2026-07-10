package user

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Backup codes — 10 one-time recovery codes generated alongside TOTP so
// users can still log in when they lose their authenticator. Plaintext is
// returned ONCE from Generate/Regenerate; thereafter only bcrypt hashes
// persist. Each code is consumed (used_at stamped) on first successful
// match.

const (
	BackupCodeCount      = 10
	backupCodeBytes      = 5 // 5 bytes = 40 bits → 8 base32 chars → split as A1B2-C3D4
	bcryptCostBackupCode = bcrypt.DefaultCost
)

// MFABackupCode is the storage row. Plaintext never lives here.
type MFABackupCode struct {
	ID        int64      `gorm:"column:id;primaryKey" json:"id"`
	UserID    int64      `gorm:"column:user_id;not null" json:"user_id"`
	CodeHash  string     `gorm:"column:code_hash;not null;size:120" json:"-"`
	UsedAt    *time.Time `gorm:"column:used_at" json:"used_at"`
	CreatedAt time.Time  `gorm:"column:created_at;not null" json:"created_at"`
}

func (MFABackupCode) TableName() string { return "mxid_user_mfa_backup_code" }

// BackupCodeRepository abstracts the storage so the user.Service stays
// agnostic and tests can swap an in-memory impl.
type BackupCodeRepository interface {
	ReplaceAll(ctx context.Context, userID int64, hashes []string, idGen func() int64) error
	ListActive(ctx context.Context, userID int64) ([]*MFABackupCode, error)
	MarkUsed(ctx context.Context, id int64, when time.Time) error
	CountActive(ctx context.Context, userID int64) (int, error)
	DeleteAll(ctx context.Context, userID int64) error
}

type backupCodeRepo struct{ db *gorm.DB }

// NewBackupCodeRepository builds a gorm-backed repo.
func NewBackupCodeRepository(db *gorm.DB) BackupCodeRepository { return &backupCodeRepo{db: db} }

// ReplaceAll wipes the user's existing backup codes and inserts the new
// hash set in a single transaction — used by Generate and Regenerate so
// the user can't end up with stale codes still being valid.
func (r *backupCodeRepo) ReplaceAll(ctx context.Context, userID int64, hashes []string, idGen func() int64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&MFABackupCode{}).Error; err != nil {
			return err
		}
		now := time.Now()
		rows := make([]MFABackupCode, len(hashes))
		for i, h := range hashes {
			rows[i] = MFABackupCode{ID: idGen(), UserID: userID, CodeHash: h, CreatedAt: now}
		}
		if len(rows) > 0 {
			if err := tx.Create(&rows).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *backupCodeRepo) ListActive(ctx context.Context, userID int64) ([]*MFABackupCode, error) {
	var rows []*MFABackupCode
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND used_at IS NULL", userID).
		Order("created_at ASC").
		Find(&rows).Error
	return rows, err
}

// MarkUsed atomically consumes a backup code: the `used_at IS NULL` predicate +
// RowsAffected check make it single-use even under a race. Two concurrent logins
// presenting the same code both pass VerifyBackupCode's bcrypt match, but only
// the UPDATE that flips used_at first affects a row; the loser sees
// RowsAffected==0 and is rejected as an invalid code (no double-consume).
func (r *backupCodeRepo) MarkUsed(ctx context.Context, id int64, when time.Time) error {
	res := r.db.WithContext(ctx).
		Model(&MFABackupCode{}).
		Where("id = ? AND used_at IS NULL", id).
		Update("used_at", when)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrMFAInvalidCode
	}
	return nil
}

func (r *backupCodeRepo) CountActive(ctx context.Context, userID int64) (int, error) {
	var n int64
	err := r.db.WithContext(ctx).
		Model(&MFABackupCode{}).
		Where("user_id = ? AND used_at IS NULL", userID).
		Count(&n).Error
	return int(n), err
}

func (r *backupCodeRepo) DeleteAll(ctx context.Context, userID int64) error {
	return r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&MFABackupCode{}).Error
}

// ----- service surface -----

// GenerateBackupCodes wipes any existing codes and produces 10 new
// plaintext codes. Returns the plaintext to the caller (one-shot display)
// and stores only the bcrypt hashes. Idempotent — calling twice gives a
// fresh set each time.
func (s *Service) GenerateBackupCodes(ctx context.Context, userID int64) ([]string, error) {
	if s.backupRepo == nil {
		return nil, errors.New("backup codes repository not wired")
	}
	codes := make([]string, 0, BackupCodeCount)
	hashes := make([]string, 0, BackupCodeCount)
	for i := 0; i < BackupCodeCount; i++ {
		code, err := newBackupCode()
		if err != nil {
			return nil, err
		}
		h, err := bcrypt.GenerateFromPassword([]byte(normalizeBackupCode(code)), bcryptCostBackupCode)
		if err != nil {
			return nil, fmt.Errorf("hash backup code: %w", err)
		}
		codes = append(codes, code)
		hashes = append(hashes, string(h))
	}
	if err := s.backupRepo.ReplaceAll(ctx, userID, hashes, s.idGen.Generate); err != nil {
		return nil, fmt.Errorf("persist backup codes: %w", err)
	}
	return codes, nil
}

// CountBackupCodes returns how many UNUSED codes the user has left. UI
// uses this to warn "only N codes left, regenerate before they run out".
func (s *Service) CountBackupCodes(ctx context.Context, userID int64) (int, error) {
	if s.backupRepo == nil {
		return 0, nil
	}
	return s.backupRepo.CountActive(ctx, userID)
}

// ConsumeBackupCode validates and marks-used a single backup code. Returns
// nil on success, ErrMFAInvalidCode on mismatch. Bcrypt's compare runs in
// constant time per hash → O(N) for the active set; N≤10 so cost is bounded.
func (s *Service) ConsumeBackupCode(ctx context.Context, userID int64, code string) error {
	if s.backupRepo == nil {
		return ErrMFAInvalidCode
	}
	normalized := normalizeBackupCode(code)
	if normalized == "" {
		return ErrMFAInvalidCode
	}
	rows, err := s.backupRepo.ListActive(ctx, userID)
	if err != nil {
		return fmt.Errorf("list backup codes: %w", err)
	}
	for _, r := range rows {
		if bcrypt.CompareHashAndPassword([]byte(r.CodeHash), []byte(normalized)) == nil {
			return s.backupRepo.MarkUsed(ctx, r.ID, time.Now())
		}
	}
	return ErrMFAInvalidCode
}

// DeleteBackupCodes wipes the user's set — called when TOTP is disabled
// so old codes don't linger.
func (s *Service) DeleteBackupCodes(ctx context.Context, userID int64) error {
	if s.backupRepo == nil {
		return nil
	}
	return s.backupRepo.DeleteAll(ctx, userID)
}

// newBackupCode mints one 8-char hyphenated code like "A1B2-C3D4". Uses
// crypto/rand + Crockford-friendly base32 so users can read them off
// paper without confusing 0/O and 1/I (base32 std excludes 0/1).
func newBackupCode() (string, error) {
	b := make([]byte, backupCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	if len(enc) < 8 {
		return "", fmt.Errorf("backup code too short: %d", len(enc))
	}
	enc = enc[:8]
	return enc[:4] + "-" + enc[4:], nil
}

// normalizeBackupCode strips hyphens + spaces, uppercases. Lets users
// paste back the displayed format ("A1B2-C3D4") or the raw 8 chars.
func normalizeBackupCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) != 8 {
		return ""
	}
	return s
}
