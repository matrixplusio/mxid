package app

// OIDC-related adapter shims. These bridge the protocol/oidc package
// (which intentionally has no business-domain imports) to concrete
// services defined under internal/domain/*. Kept in a separate file so
// the main wiring stays readable.

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/bootstrap"
	appdomain "github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/appaccess"
	"github.com/imkerbos/mxid/internal/domain/approle"
)

// appProtocolResolver adapts the app domain service to access.ProtocolResolver:
// given an app id, it returns the app's SSO protocol ("oidc"|"saml"|"cas") so
// the CompositeTerminator can pick the matching downstream-logout handler.
type appProtocolResolver struct{ svc *appdomain.Service }

func (r appProtocolResolver) ProtocolForApp(ctx context.Context, appID int64) (string, error) {
	application, err := r.svc.GetByID(ctx, appID)
	if err != nil {
		return "", err
	}
	return application.Protocol, nil
}

type oidcAccessAdapter struct{ svc *appaccess.Service }

func (a *oidcAccessAdapter) CheckAppAccess(ctx context.Context, userID, appID, tenantID int64) (bool, string, error) {
	dec, err := a.svc.CanAccess(ctx, userID, appID, tenantID)
	if err != nil {
		return false, "", err
	}
	return dec.Allowed, dec.Reason, nil
}

type oidcAppRolesAdapter struct{ svc *approle.Service }

func (a *oidcAppRolesAdapter) ResolveAppRoles(ctx context.Context, userID, appID, tenantID int64) ([]string, error) {
	return a.svc.ResolveCodes(ctx, userID, appID, tenantID)
}

type accessMatcher struct{ app *bootstrap.App }

func newAccessMatcher(app *bootstrap.App) *accessMatcher { return &accessMatcher{app: app} }

func (m *accessMatcher) UserInGroup(ctx context.Context, userID, groupID int64) (bool, error) {
	var n int64
	err := m.app.DB.WithContext(ctx).Table("mxid_user_group_member").
		Where("user_id = ? AND group_id = ?", userID, groupID).Count(&n).Error
	return n > 0, err
}

func (m *accessMatcher) UserInOrg(ctx context.Context, userID, orgID int64) (bool, error) {
	const q = `SELECT COUNT(*) FROM mxid_user_org uo INNER JOIN mxid_org o ON o.id = uo.org_id AND o.deleted_at IS NULL WHERE uo.user_id = ? AND (o.id = ? OR o.path <@ (SELECT path FROM mxid_org WHERE id = ?))`
	var n int64
	err := m.app.DB.WithContext(ctx).Raw(q, userID, orgID, orgID).Scan(&n).Error
	return n > 0, err
}

func (m *accessMatcher) UserHasRole(ctx context.Context, userID, roleID int64) (bool, error) {
	var n int64
	err := m.app.DB.WithContext(ctx).Table("mxid_role_binding").
		Where("role_id = ? AND subject_type = 'user' AND subject_id = ?", roleID, userID).Count(&n).Error
	return n > 0, err
}

// accessSubjectMatcher adapts *accessMatcher (UserInGroup/UserInOrg/UserHasRole
// returning (bool, error), tenant-agnostic) to the JIT access package's
// access.SubjectMatcher interface (tenant-scoped, error-swallowing bool). The
// underlying membership tables are not tenant-partitioned in CE, so tenantID is
// accepted for interface compatibility but not used in the lookup; a lookup
// error is treated as "no match" (fail-closed), matching the appaccess posture.
type accessSubjectMatcher struct{ m *accessMatcher }

func newAccessSubjectMatcher(app *bootstrap.App) *accessSubjectMatcher {
	return &accessSubjectMatcher{m: newAccessMatcher(app)}
}

func (a *accessSubjectMatcher) UserInGroup(ctx context.Context, _ /*tenantID*/, userID, groupID int64) bool {
	ok, err := a.m.UserInGroup(ctx, userID, groupID)
	return err == nil && ok
}

func (a *accessSubjectMatcher) UserInOrg(ctx context.Context, _ /*tenantID*/, userID, orgID int64) bool {
	ok, err := a.m.UserInOrg(ctx, userID, orgID)
	return err == nil && ok
}

func (a *accessSubjectMatcher) UserHasRole(ctx context.Context, _ /*tenantID*/, userID, roleID int64) bool {
	ok, err := a.m.UserHasRole(ctx, userID, roleID)
	return err == nil && ok
}

type appLabelResolver struct{ app *bootstrap.App }

func newAppLabelResolver(app *bootstrap.App) *appLabelResolver { return &appLabelResolver{app: app} }

func (r *appLabelResolver) App(_ *gin.Context, id int64) (string, string) {
	var row struct{ Name, Code string }
	_ = r.app.DB.Table("mxid_app").Where("id = ? AND deleted_at IS NULL", id).Take(&row).Error
	return row.Name, row.Code
}

func (r *appLabelResolver) AppGroup(_ *gin.Context, id int64) (string, string) {
	var row struct{ Name, Code string }
	_ = r.app.DB.Table("mxid_app_group").Where("id = ? AND deleted_at IS NULL", id).Take(&row).Error
	return row.Name, row.Code
}

type accessSubjectResolver struct{ app *bootstrap.App }

func newAccessSubjectResolver(app *bootstrap.App) *accessSubjectResolver {
	return &accessSubjectResolver{app: app}
}

func (r *accessSubjectResolver) Resolve(_ *gin.Context, subjectType string, id int64) (string, string) {
	switch subjectType {
	case appaccess.SubjectUser:
		var row struct{ Username, DisplayName string }
		_ = r.app.DB.Table("mxid_user").Select("username, COALESCE(display_name, '') as display_name").Where("id = ?", id).Take(&row).Error
		if row.DisplayName != "" {
			return row.DisplayName, row.Username
		}
		return row.Username, row.Username
	case appaccess.SubjectGroup:
		var row struct{ Name, Code string }
		_ = r.app.DB.Table("mxid_user_group").Where("id = ? AND deleted_at IS NULL", id).Take(&row).Error
		return row.Name, row.Code
	case appaccess.SubjectOrg:
		var row struct{ Name, Code string }
		_ = r.app.DB.Table("mxid_organization").Where("id = ? AND deleted_at IS NULL", id).Take(&row).Error
		return row.Name, row.Code
	case appaccess.SubjectRole:
		var row struct{ Name, Code string }
		_ = r.app.DB.Table("mxid_role").Where("id = ? AND deleted_at IS NULL", id).Take(&row).Error
		return row.Name, row.Code
	}
	return "", ""
}
