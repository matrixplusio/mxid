package app

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/audit"
)

// runVerifyAudit walks every (tenant_id, chain_class) chain head recorded in
// mxid_audit_chain_head and recomputes its HMAC hash chain from genesis,
// printing a per-chain status line. It is a read-only operator/cron check —
// invoked via the `verify-audit` CLI subcommand (see the dispatch in Run,
// app/run.go) — and must never run alongside the Chainer goroutine or the
// HTTP server, since VerifyChain only reads.
//
// Returns a non-nil error (causing Run to os.Exit(1)) if the key can't be
// decoded, a chain read fails, or any chain fails verification, so CI/cron
// wrappers can detect tampering from the exit code alone.
func runVerifyAudit(a *bootstrap.App) error {
	key, err := base64.StdEncoding.DecodeString(a.Config.Crypto.AuditChainKey)
	if err != nil {
		return fmt.Errorf("decode crypto.audit_chain_key (must be base64): %w", err)
	}
	if len(key) == 0 {
		return fmt.Errorf("crypto.audit_chain_key is empty; export MXID_CRYPTO_AUDIT_CHAIN_KEY=$(openssl rand -base64 32)")
	}

	ctx := context.Background()
	var heads []audit.ChainHead
	if err := a.DB.WithContext(ctx).Order("tenant_id, chain_class").Find(&heads).Error; err != nil {
		return fmt.Errorf("load chain heads: %w", err)
	}

	failed := false
	for _, h := range heads {
		res, err := audit.VerifyChain(ctx, a.DB, key, h.TenantID, h.ChainClass)
		if err != nil {
			return fmt.Errorf("verify chain tenant=%d class=%s: %w", h.TenantID, h.ChainClass, err)
		}
		status := "OK"
		if !res.OK {
			failed = true
			status = fmt.Sprintf("FAIL at seq %d (%s)", res.FailSeq, res.Reason)
		}
		fmt.Printf("chain tenant=%d class=%s: verified through seq %d — %s\n",
			h.TenantID, h.ChainClass, res.VerifiedThrough, status)
	}
	if failed {
		return fmt.Errorf("one or more audit chains failed verification")
	}
	return nil
}
