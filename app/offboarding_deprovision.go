package app

import (
	"context"
	"encoding/json"

	"github.com/imkerbos/mxid/internal/domain/offboarding"
	"github.com/imkerbos/mxid/internal/outbox"
)

// offboardDeprovisionEnqueuer implements offboarding.DeprovisionEnqueuer by
// dropping an offboarding.scim message onto the durable outbox. The handler for
// that kind is registered ONLY by the EE SCIM connector; CE classifies no app
// as L2, so this is never called in a CE binary.
type offboardDeprovisionEnqueuer struct {
	outbox outbox.Repository
}

// scimDeprovisionPayload is the outbox body the EE SCIM connector consumes. It
// carries enough to match the downstream account (email / username) and look up
// the app's provisioning config (app_id) at delivery time.
type scimDeprovisionPayload struct {
	AppID    int64  `json:"app_id,string"`
	UserID   int64  `json:"user_id,string"`
	Username string `json:"username"`
	Email    string `json:"email"`
	TenantID int64  `json:"tenant_id,string"`
}

// Enqueue durably queues a downstream deprovision for one app.
func (d offboardDeprovisionEnqueuer) Enqueue(ctx context.Context, tenantID, appID, userID int64, username, email string) error {
	body, err := json.Marshal(scimDeprovisionPayload{
		AppID:    appID,
		UserID:   userID,
		Username: username,
		Email:    email,
		TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	return d.outbox.Enqueue(ctx, &outbox.Message{
		Kind:     offboarding.ScimKind,
		TenantID: tenantID,
		Payload:  body,
	})
}
