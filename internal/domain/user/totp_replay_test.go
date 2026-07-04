package user

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/imkerbos/mxid/pkg/crypto"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// totpStubRepo implements just the MFA reads/writes VerifyTOTP touches. It
// embeds Repository so the unused methods exist (and panic loudly if a future
// VerifyTOTP change starts calling them, surfacing the test gap).
type totpStubRepo struct {
	Repository
	mfa *UserMFA
}

func (r *totpStubRepo) GetMFA(_ context.Context, _ int64, _ string) (*UserMFA, error) {
	if r.mfa == nil {
		return nil, gorm.ErrRecordNotFound
	}
	return r.mfa, nil
}

func (r *totpStubRepo) UpdateMFA(_ context.Context, m *UserMFA) error {
	r.mfa = m
	return nil
}

// newTOTPService builds a Service with a masterkey + redis-backed replay guard
// and a single enrolled+verified TOTP factor, returning the base32 secret so
// the test can mint live codes.
func newTOTPService(t *testing.T) (*Service, *totpStubRepo, string, *redis.Client) {
	t.Helper()
	mk, err := crypto.NewMasterKey(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("masterkey: %v", err)
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "MXID", AccountName: "tester",
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("totp gen: %v", err)
	}
	enc, err := mk.Encrypt([]byte(key.Secret()))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	repo := &totpStubRepo{mfa: &UserMFA{
		ID: 1, UserID: 42, Type: MFATypeTotp, Secret: &enc, Verified: true,
	}}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	svc := &Service{repo: repo, masterKey: mk, issuer: "MXID"}
	svc.SetTOTPReplayGuard(rdb)
	return svc, repo, key.Secret(), rdb
}

// A code that validates once must be REJECTED on a second use within the same
// step window — the core single-use (replay) guarantee.
func TestVerifyTOTP_ReplayRejected(t *testing.T) {
	svc, _, secret, _ := newTOTPService(t)
	ctx := context.Background()

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}

	if err := svc.VerifyTOTP(ctx, 42, code); err != nil {
		t.Fatalf("first VerifyTOTP should succeed, got %v", err)
	}
	if err := svc.VerifyTOTP(ctx, 42, code); err == nil {
		t.Fatal("second VerifyTOTP with the SAME code must fail (replay), got nil")
	} else if err != ErrMFACodeReused {
		t.Fatalf("replay should map to ErrMFACodeReused, got %v", err)
	}
}

// A genuinely wrong code is rejected and does NOT consume the step, so the
// correct current code still works afterwards.
func TestVerifyTOTP_WrongCodeThenValid(t *testing.T) {
	svc, _, secret, _ := newTOTPService(t)
	ctx := context.Background()

	if err := svc.VerifyTOTP(ctx, 42, "000000"); err != ErrMFAInvalidCode {
		// 000000 could (1 in 1e6) be the live code; tolerate that rare case.
		if err == nil {
			t.Skip("000000 happened to be the live code; skipping")
		}
		t.Fatalf("wrong code want ErrMFAInvalidCode, got %v", err)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if err := svc.VerifyTOTP(ctx, 42, code); err != nil {
		t.Fatalf("valid code after a wrong guess should succeed, got %v", err)
	}
}

// The replay guard fails CLOSED: with redis unreachable, a valid code is
// rejected rather than admitted (so a store outage can't reopen the window).
func TestVerifyTOTP_ReplayGuardFailClosed(t *testing.T) {
	svc, _, secret, rdb := newTOTPService(t)
	ctx := context.Background()
	_ = rdb.Close() // force store errors on claim

	code, _ := totp.GenerateCode(secret, time.Now())
	if err := svc.VerifyTOTP(ctx, 42, code); err != ErrMFAInvalidCode {
		t.Fatalf("with redis down the claim must fail closed -> ErrMFAInvalidCode, got %v", err)
	}
}

// First-enrollment verify (Verified=false) must also claim the step so the
// enrollment code can't be replayed once to "double enroll" / reuse.
func TestVerifyTOTP_EnrollVerifyClaimsStep(t *testing.T) {
	svc, repo, secret, _ := newTOTPService(t)
	repo.mfa.Verified = false // simulate fresh enrollment
	ctx := context.Background()

	code, _ := totp.GenerateCode(secret, time.Now())
	if err := svc.VerifyTOTP(ctx, 42, code); err != nil {
		t.Fatalf("enroll verify should succeed, got %v", err)
	}
	if !repo.mfa.Verified {
		t.Fatal("enroll verify should promote Verified=true")
	}
	if err := svc.VerifyTOTP(ctx, 42, code); err == nil {
		t.Fatal("replaying the enrollment code must fail, got nil")
	}
}
