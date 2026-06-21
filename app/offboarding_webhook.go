package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/imkerbos/mxid/internal/domain/offboarding"
	"github.com/imkerbos/mxid/internal/domain/setting"
	"github.com/imkerbos/mxid/internal/outbox"
	"github.com/imkerbos/mxid/pkg/safehttp"
)

// offboardWebhookDispatcher implements offboarding.WebhookDispatcher: it gates
// on the runtime settings flag and durably enqueues the payload onto the
// transactional outbox, so the notification survives a crash and retries.
type offboardWebhookDispatcher struct {
	settings *setting.Service
	outbox   outbox.Repository
}

// Enabled reports whether a webhook is configured + on for the tenant.
func (d offboardWebhookDispatcher) Enabled(ctx context.Context, tenantID int64) bool {
	cfg, err := d.settings.OffboardingWebhook(ctx, tenantID)
	return err == nil && cfg.Enabled && cfg.URL != ""
}

// Enqueue durably queues the webhook delivery.
func (d offboardWebhookDispatcher) Enqueue(ctx context.Context, tenantID int64, payload offboarding.WebhookPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return d.outbox.Enqueue(ctx, &outbox.Message{
		Kind:     offboarding.WebhookKind,
		TenantID: tenantID,
		Payload:  body,
	})
}

// newOffboardingWebhookHandler returns the outbox handler that delivers the
// signed offboarding webhook. The URL/secret are read at DELIVERY time (not
// enqueue time) so a rotated config applies to already-queued messages. The
// body is HMAC-SHA256 signed with the shared secret so the receiver can verify
// authenticity. All egress goes through safehttp (SSRF guard, re-checks the
// resolved IP on every dial + redirect) since the URL is admin-supplied.
func newOffboardingWebhookHandler(settings *setting.Service) outbox.Handler {
	client := safehttp.New(safehttp.WithTimeout(10 * time.Second))
	return func(ctx context.Context, msg *outbox.Message) error {
		cfg, err := settings.OffboardingWebhook(ctx, msg.TenantID)
		if err != nil {
			return fmt.Errorf("load webhook config: %w", err)
		}
		if !cfg.Enabled || cfg.URL == "" {
			// Turned off since the message was enqueued — nothing to deliver.
			// Returning nil marks it done rather than retrying forever.
			return nil
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(msg.Payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-MXID-Event", "offboarding.initiated")
		if cfg.Secret != "" {
			mac := hmac.New(sha256.New, []byte(cfg.Secret))
			mac.Write(msg.Payload)
			req.Header.Set("X-MXID-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("post offboarding webhook: %w", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("offboarding webhook returned status %d", resp.StatusCode)
		}
		return nil
	}
}
