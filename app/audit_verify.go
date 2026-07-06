package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"strings"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/audit"
	"github.com/imkerbos/mxid/pkg/crypto"
)

// anchorKeyRegistry builds the KeyRegistry used to verify anchor signatures:
// the CURRENT anchor key (derived from crypto.audit_anchor_key) plus every
// RETIRED public key listed in crypto.audit_anchor_retired_pubkeys (comma-
// separated base64 ed25519 public keys). Keeping retired keys registered lets
// old anchors — signed before a key rotation — still verify.
//
// If the anchor key is unset, anchoring is disabled: this returns an empty
// registry and a nil error rather than an error, so verify-audit / audit-export
// degrade gracefully (VerifyAnchorsWithSink and BuildExport both tolerate an
// empty registry — there's simply nothing to anchor/prove).
// parsePubKeys decodes a comma-separated list of base64 raw ed25519 public keys,
// skipping blanks. Each key must be exactly ed25519.PublicKeySize bytes so a
// fat-fingered value fails here with a clear error instead of panicking later
// inside ed25519.Verify.
func parsePubKeys(csv string) ([]ed25519.PublicKey, error) {
	var pubs []ed25519.PublicKey
	for _, raw := range strings.Split(csv, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("decode audit anchor pubkey %q: %w", s, err)
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("audit anchor pubkey %q is %d bytes, want %d", s, len(b), ed25519.PublicKeySize)
		}
		pubs = append(pubs, ed25519.PublicKey(b))
	}
	return pubs, nil
}

func anchorKeyRegistry(a *bootstrap.App) (audit.KeyRegistry, error) {
	var pubs []ed25519.PublicKey

	if seedB64 := strings.TrimSpace(a.Config.Crypto.AuditAnchorKey); seedB64 != "" {
		seed, err := base64.StdEncoding.DecodeString(seedB64)
		if err != nil {
			return nil, fmt.Errorf("decode audit anchor key: %w", err)
		}
		priv, err := crypto.Ed25519FromSeed(seed)
		if err != nil {
			return nil, fmt.Errorf("audit anchor key invalid: %w", err)
		}
		pubs = append(pubs, priv.Public().(ed25519.PublicKey))
	}

	retired, err := parsePubKeys(a.Config.Crypto.AuditAnchorRetiredPubKeys)
	if err != nil {
		return nil, err
	}
	pubs = append(pubs, retired...)

	return audit.NewKeyRegistry(pubs...), nil
}

// runVerifyAudit walks every (tenant_id, chain_class) chain head recorded in
// mxid_audit_chain_head and recomputes its HMAC hash chain from genesis,
// printing a per-chain status line. It is a read-only operator/cron check —
// invoked via the `verify-audit` CLI subcommand (see the dispatch in Run,
// app/run.go) — and must never run alongside the Chainer goroutine or the
// HTTP server, since VerifyChain only reads.
//
// Anchor verification uses VerifyAnchorsWithSink (sink-diff): it cross-checks
// the DB's mxid_audit_anchor rows against the external AnchorSink, so a
// deleted-or-forged DB anchor row is caught even though the HMAC chain and the
// remaining anchors look internally consistent. anchorKeyRegistry supplies
// every registered key (current + retired), so a rotation doesn't break
// verification of anchors signed under the old key.
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

	reg, err := anchorKeyRegistry(a)
	if err != nil {
		return err
	}
	sink := audit.NewFileSink(a.Config.Audit.AnchorSinkPath)

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

		if len(reg) > 0 {
			ares, aerr := audit.VerifyAnchorsWithSink(ctx, a.DB, sink, reg, h.TenantID, h.ChainClass)
			if aerr != nil {
				return aerr
			}
			astatus := "OK"
			if !ares.OK {
				failed = true
				astatus = fmt.Sprintf("FAIL from seq %d (%s)", ares.FailFromSeq, ares.Reason)
			}
			fmt.Printf("  anchors tenant=%d class=%s: verified through seq %d — %s\n",
				h.TenantID, h.ChainClass, ares.AnchoredThrough, astatus)
		}
	}
	if failed {
		return fmt.Errorf("one or more audit chains failed verification")
	}
	return nil
}

// runAuditExport builds a third-party-verifiable export bundle (entries +
// overlapping signed anchors + the public keys needed to verify them) for
// [--from,--to] of one (--tenant,--class) chain, and writes it to --out as
// entries.jsonl + proof.json (see audit.WriteExport). It is invoked via the
// `audit-export` CLI subcommand (see the dispatch in Run, app/run.go) and
// needs the DB (hence it runs after bootstrap.NewApp, unlike verify-export).
func runAuditExport(a *bootstrap.App, args []string) error {
	fs := flag.NewFlagSet("audit-export", flag.ContinueOnError)
	tenant := fs.Int64("tenant", 0, "tenant id")
	class := fs.String("class", "data", "chain class")
	from := fs.Int64("from", 0, "from seq (inclusive)")
	to := fs.Int64("to", 0, "to seq (inclusive)")
	out := fs.String("out", "", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}

	reg, err := anchorKeyRegistry(a)
	if err != nil {
		return err
	}

	ctx := context.Background()
	b, err := audit.BuildExport(ctx, a.DB, reg, *tenant, *class, *from, *to)
	if err != nil {
		return fmt.Errorf("build export: %w", err)
	}
	if err := audit.WriteExport(*out, b); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	fmt.Printf("exported tenant=%d class=%s seq %d..%d -> %s (%d entries, %d anchors)\n",
		b.TenantID, b.ChainClass, b.FromSeq, b.ToSeq, *out, len(b.Entries), len(b.Anchors))
	return nil
}

// runVerifyExport proves an export bundle OFFLINE — no database, no HMAC key,
// no app/bootstrap dependency at all. A third party who received the export
// directory (from runAuditExport) and a trusted public key runs this to prove
// tamper-freedom on their own, independent of the mxid deployment that
// produced it. It is invoked via the `verify-export` CLI subcommand, wired in
// Run (app/run.go) BEFORE bootstrap.NewApp — it must never require a DB/config.
func runVerifyExport(args []string) error {
	fs := flag.NewFlagSet("verify-export", flag.ContinueOnError)
	dir := fs.String("dir", "", "export directory (containing entries.jsonl + proof.json)")
	trust := fs.String("trust", "", "comma-separated base64 ed25519 public keys to trust")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}

	pubs, err := parsePubKeys(*trust)
	if err != nil {
		return err
	}
	reg := audit.NewKeyRegistry(pubs...)

	b, err := audit.ReadExport(*dir)
	if err != nil {
		return fmt.Errorf("read export: %w", err)
	}
	res, err := audit.VerifyExport(b, reg)
	if err != nil {
		return fmt.Errorf("verify export: %w", err)
	}
	status := "OK"
	if !res.OK {
		status = fmt.Sprintf("FAIL from seq %d (%s)", res.FailFromSeq, res.Reason)
	}
	fmt.Printf("export tenant=%d class=%s: proved through seq %d — %s\n",
		b.TenantID, b.ChainClass, res.AnchoredThrough, status)
	if !res.OK {
		return fmt.Errorf("export verification failed")
	}
	return nil
}
