// Package sms is the outbound SMS abstraction. Mirrors pkg/mailer in shape:
// the high-level service loads provider config per-send from the setting
// domain (so admins can swap providers without restarting) and dispatches
// to a provider-specific Sender.
//
// Provider matrix:
//
//	aliyun   → Alibaba Cloud SMS (HMAC-SHA1 over query params, stdlib only)
//	tencent  → Tencent Cloud SMS v3 (HMAC-SHA256 signing, stdlib only)
//	twilio   → Twilio REST API (HTTP Basic auth, x-www-form-urlencoded)
//
// All three providers share the same SendCode signature: (ctx, phone,
// code, [vars]). vars carries optional template parameters; providers that
// take a template ID + slot values use them, others ignore.
package sms

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/pkg/safehttp"
)

// smsHTTPClient is the shared outbound client for every SMS provider. It is
// SSRF-safe and, critically, timeout-bounded: the stdlib default client has no
// timeout, so a slow/hung provider endpoint would pile up handler goroutines on
// the unauthenticated OTP-send path (/auth/sms/send) until the process starves.
// All three providers target public HTTPS APIs, so the SSRF guard is compatible.
var smsHTTPClient = safehttp.New(safehttp.WithTimeout(10 * time.Second))

// ErrDisabled — the SMS service is not enabled or has no provider chosen.
// Callers (auth handlers) should map this to a 503 / 403 with a hint.
var ErrDisabled = errors.New("sms service is not enabled")

// ErrProviderNotSupported — the configured provider id has no factory
// registered. Distinguished from "not enabled" because it's a config bug,
// not an admin choice.
var ErrProviderNotSupported = errors.New("sms provider not supported")

// Sender is the provider-specific transport. Phone is E.164 (e.g.
// +8613800138000); code is the 6-digit OTP. vars carries template-side
// substitutions (varies per provider).
type Sender interface {
	SendCode(ctx context.Context, cfg setting.SMS, phone, code string) error
}

// Service is the high-level entry point. Use:
//
//	svc := sms.New(settingService)
//	if err := svc.SendOTP(ctx, tenantID, phone, code); err != nil { ... }
type Service struct {
	settings *setting.Service
}

func New(settings *setting.Service) *Service {
	return &Service{settings: settings}
}

// SendOTP renders + sends a one-time password to the given phone using
// the tenant's active SMS provider. Returns ErrDisabled when the
// service is off or no provider is configured.
func (s *Service) SendOTP(ctx context.Context, tenantID int64, phone, code string) error {
	cfg, err := s.settings.SMS(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("load sms config: %w", err)
	}
	if !cfg.Enabled {
		return ErrDisabled
	}
	sender, err := senderFor(cfg.Provider)
	if err != nil {
		return err
	}
	return sender.SendCode(ctx, cfg, phone, code)
}

func senderFor(provider string) (Sender, error) {
	switch provider {
	case "aliyun":
		return aliyunSender{}, nil
	case "tencent":
		return tencentSender{}, nil
	case "twilio":
		return twilioSender{}, nil
	case "":
		return nil, ErrDisabled
	default:
		return nil, fmt.Errorf("%w: %s", ErrProviderNotSupported, provider)
	}
}
