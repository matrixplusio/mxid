package app

import (
	"context"

	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/appaccess"
	"github.com/imkerbos/mxid/internal/domain/offboarding"
	"github.com/imkerbos/mxid/internal/domain/provisioning"
	"github.com/imkerbos/mxid/pkg/ee/license"
	"github.com/imkerbos/mxid/pkg/ee/registry"
)

// offboardFootprint bridges the appaccess + app services onto the offboarding
// AppFootprint interface, so an offboard can list every app the departing user
// could reach (for the review checklist) without the offboarding domain
// importing either service.
type offboardFootprint struct {
	access       *appaccess.Service
	apps         *app.Service
	provisioning *provisioning.Service
}

// scimAvailable reports whether L2 downstream deprovisioning can run in this
// binary: the SCIM connector must be built in (EE) AND licensed. CE binaries
// register no SCIM feature, so every app stays L1 (review-only).
func scimAvailable() bool {
	return registry.IsFeatureRegistered(string(license.FeatureSCIM)) &&
		license.Current().Has(license.FeatureSCIM)
}

// ForUser returns the user's authorized apps, denormalized into review refs.
// An app is L2 (auto-deprovision downstream) when its provisioning is enabled
// AND the SCIM connector is available; otherwise L1 (SSO cut + manual review).
func (f offboardFootprint) ForUser(ctx context.Context, userID, tenantID int64) ([]offboarding.AppRef, error) {
	ids, err := f.access.AppsForUser(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	apps, err := f.apps.GetByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	scim := scimAvailable()
	refs := make([]offboarding.AppRef, 0, len(apps))
	for _, a := range apps {
		tier := offboarding.TierL1
		if scim && f.provisioning != nil && f.provisioning.Enabled(ctx, a.ID) {
			tier = offboarding.TierL2
		}
		refs = append(refs, offboarding.AppRef{
			ID:   a.ID,
			Name: a.Name,
			Code: a.Code,
			Tier: tier,
		})
	}
	return refs, nil
}
