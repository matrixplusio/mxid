package app

// portal.* querier adapters wiring user / app / session / mfa / identity
// domain modules into the portal gateway's interfaces.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/imkerbos/mxid/internal/bootstrap"
	"github.com/imkerbos/mxid/internal/domain/apitoken"
	"github.com/imkerbos/mxid/internal/domain/app"
	"github.com/imkerbos/mxid/internal/domain/appaccess"
	"github.com/imkerbos/mxid/internal/domain/audit"
	"github.com/imkerbos/mxid/internal/domain/user"
	"github.com/imkerbos/mxid/internal/gateway/portal"
	"github.com/imkerbos/mxid/pkg/event"
	"github.com/imkerbos/mxid/pkg/session"
	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

/* ─────────── User ─────────── */

type portalUserQuerierAdapter struct {
	userModule *user.Module
}

func buildPortalUserQuerier(m *user.Module) portal.UserQuerier {
	return &portalUserQuerierAdapter{userModule: m}
}

func (a *portalUserQuerierAdapter) GetByID(ctx context.Context, userID int64) (*portal.UserInfo, error) {
	u, err := a.userModule.Repo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	info := &portal.UserInfo{
		ID: u.ID, Username: u.Username, Status: u.Status,
		LastLoginAt: u.LastLoginAt, EmailVerified: u.EmailVerified,
	}
	if u.DisplayName != nil {
		info.DisplayName = *u.DisplayName
	}
	if u.Email != nil {
		info.Email = *u.Email
	}
	if u.Phone != nil {
		info.Phone = *u.Phone
	}
	if u.Avatar != nil {
		info.Avatar = *u.Avatar
	}
	return info, nil
}

func (a *portalUserQuerierAdapter) GetDetail(ctx context.Context, userID int64) (*portal.UserDetail, error) {
	d, err := a.userModule.Service.GetDetail(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &portal.UserDetail{
		Gender: d.Gender, Birthday: d.Birthday, Address: d.Address,
		EmployeeNo: d.EmployeeNo, JobTitle: d.JobTitle, Department: d.Department,
	}, nil
}

// UpdateProfile writes the mutable self-service profile fields directly via
// the repo (bypassing user.Service.Update, which also handles admin-only
// fields like status). It still has to replicate Update's email/phone
// uniqueness checks below — otherwise a duplicate would hit the DB's unique
// constraint and surface as a raw, undiscriminated error (500) instead of
// the same ErrEmailExists/ErrPhoneExists 409 the console admin-edit path
// reports.
func (a *portalUserQuerierAdapter) UpdateProfile(ctx context.Context, userID int64, displayName, phone, email string) error {
	u, err := a.userModule.Repo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if displayName != "" {
		u.DisplayName = &displayName
	}
	pCopy := phone
	newPhone := &pCopy
	if phone == "" {
		newPhone = nil
	}
	if !equalStringPtr(u.Phone, newPhone) && newPhone != nil {
		if _, err := a.userModule.Repo.GetByPhone(ctx, u.TenantID, *newPhone); err == nil {
			return user.ErrPhoneExists
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check phone: %w", err)
		}
	}
	u.Phone = newPhone

	eCopy := email
	newEmail := &eCopy
	if email == "" {
		newEmail = nil
	}
	emailChanged := !equalStringPtr(u.Email, newEmail)
	if emailChanged && newEmail != nil {
		if _, err := a.userModule.Repo.GetByEmail(ctx, u.TenantID, *newEmail); err == nil {
			return user.ErrEmailExists
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check email: %w", err)
		}
	}
	u.Email = newEmail
	if emailChanged {
		u.EmailVerified = false
		u.EmailVerifiedAt = nil
	}
	return a.userModule.Repo.Update(ctx, u)
}

func equalStringPtr(a, b *string) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	}
	return *a == *b
}

func (a *portalUserQuerierAdapter) MarkEmailVerified(ctx context.Context, userID int64) error {
	u, err := a.userModule.Repo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.EmailVerified {
		return nil
	}
	now := time.Now()
	u.EmailVerified = true
	u.EmailVerifiedAt = &now
	return a.userModule.Repo.Update(ctx, u)
}

func (a *portalUserQuerierAdapter) GetEmail(ctx context.Context, userID int64) (string, error) {
	u, err := a.userModule.Repo.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if u.Email == nil {
		return "", nil
	}
	return *u.Email, nil
}

func (a *portalUserQuerierAdapter) UpdateAvatar(ctx context.Context, userID int64, avatar string) error {
	u, err := a.userModule.Repo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	u.Avatar = &avatar
	return a.userModule.Repo.Update(ctx, u)
}

func (a *portalUserQuerierAdapter) ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error {
	return a.userModule.Service.ChangePassword(ctx, userID, &user.ChangePasswordRequest{
		OldPassword: oldPassword, NewPassword: newPassword,
	})
}

// LookupByEmail returns the matching user_id or 0 if no row exists. Errors
// other than not-found bubble up; not-found returns (0, nil) so the handler
// can keep the response timing identical between hit and miss.
func (a *portalUserQuerierAdapter) LookupByEmail(ctx context.Context, tenantID int64, email string) (int64, error) {
	u, err := a.userModule.Repo.GetByEmail(ctx, tenantID, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil
		}
		return 0, err
	}
	return u.ID, nil
}

// ResetPassword sets a new password without an old-password check. Used by
// the portal password-reset handler after the recovery token is consumed.
// MustChange=false so the user lands on their dashboard directly — they
// just proved possession of the email.
func (a *portalUserQuerierAdapter) ResetPassword(ctx context.Context, userID int64, newPassword string) error {
	mustChange := false
	return a.userModule.Service.ResetPassword(ctx, userID, &user.ResetPasswordRequest{
		NewPassword: newPassword,
		MustChange:  &mustChange,
	})
}

// LookupByPhone returns the matching user_id or 0 on miss. Phone strings
// pass through unchanged (caller normalises if needed).
func (a *portalUserQuerierAdapter) LookupByPhone(ctx context.Context, tenantID int64, phone string) (int64, error) {
	u, err := a.userModule.Repo.GetByPhone(ctx, tenantID, phone)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil
		}
		return 0, err
	}
	return u.ID, nil
}

// UpdateLastLogin stamps last_login_at / last_login_ip. Delegates to the same
// repo method the password engine uses, so passwordless portal logins (SMS
// OTP, magic link) record last-login consistently.
func (a *portalUserQuerierAdapter) UpdateLastLogin(ctx context.Context, userID int64, ip string) error {
	return a.userModule.Repo.UpdateLastLogin(ctx, userID, ip)
}

/* ─────────── App ─────────── */

type portalAppQuerierAdapter struct {
	app       *bootstrap.App
	idGen     *snowflake.Generator
	appModule *app.Module
	issuer    string
	accessSvc *appaccess.Service
}

func buildPortalAppQuerier(a *bootstrap.App, m *app.Module, issuer string, accessSvc *appaccess.Service) portal.AppQuerier {
	return &portalAppQuerierAdapter{app: a, idGen: a.IDGen, appModule: m, issuer: issuer, accessSvc: accessSvc}
}

func (a *portalAppQuerierAdapter) ListAuthorizedApps(ctx context.Context, userID, tenantID int64, q string) ([]*portal.AppInfo, error) {
	q = strings.TrimSpace(q)
	apps, _, err := a.appModule.Repo.List(ctx, tenantID, app.ListAppParams{Page: 1, PageSize: 100, Search: q})
	if err != nil {
		return nil, err
	}
	allowed := map[int64]struct{}{}
	if a.accessSvc != nil {
		ids, err := a.accessSvc.AppsForUser(ctx, userID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("apps for user: %w", err)
		}
		for _, id := range ids {
			allowed[id] = struct{}{}
		}
	}
	// Pre-fetch group memberships for the candidate app set so we set
	// AppInfo.GroupIDs in O(N) without N round-trips.
	candidateIDs := make([]int64, 0, len(apps))
	for _, ap := range apps {
		candidateIDs = append(candidateIDs, ap.ID)
	}
	groupsByApp := map[int64][]int64{}
	if len(candidateIDs) > 0 {
		type rel struct {
			AppID   int64 `gorm:"column:app_id"`
			GroupID int64 `gorm:"column:group_id"`
		}
		var rels []rel
		if err := a.app.DB.WithContext(ctx).
			Table("mxid_app_group_rel").
			Select("app_id, group_id").
			Where("app_id IN ?", candidateIDs).
			Scan(&rels).Error; err != nil {
			return nil, fmt.Errorf("load app group rels: %w", err)
		}
		for _, r := range rels {
			groupsByApp[r.AppID] = append(groupsByApp[r.AppID], r.GroupID)
		}
	}
	result := make([]*portal.AppInfo, 0, len(apps))
	for _, ap := range apps {
		if ap.Status != app.StatusEnabled {
			continue
		}
		if a.accessSvc != nil {
			if _, ok := allowed[ap.ID]; !ok {
				continue
			}
		}
		gids := groupsByApp[ap.ID]
		gidStrs := make([]string, len(gids))
		for i, gid := range gids {
			gidStrs[i] = strconv.FormatInt(gid, 10)
		}
		info := &portal.AppInfo{
			ID: ap.ID, Name: ap.Name, Code: ap.Code,
			Protocol: ap.Protocol, ClientType: ap.ClientType,
			GroupIDs: gidStrs,
		}
		if ap.Icon != nil {
			info.Icon = *ap.Icon
			info.LogoURL = *ap.Icon
		}
		if ap.Env != nil {
			info.Env = *ap.Env
		}
		if ap.Description != nil {
			info.Description = *ap.Description
		}
		if ap.HomeURL != nil {
			info.HomeURL = *ap.HomeURL
		}
		if ap.LoginURL != nil {
			info.LoginURL = *ap.LoginURL
		}
		result = append(result, info)
	}
	return result, nil
}

// ListAuthorizedAppGroups returns each group with the count of apps the
// requesting user can access. Groups with zero accessible apps are still
// returned so the sidebar shape stays stable (frontend hides empty ones
// if it wants — server stays declarative).
func (a *portalAppQuerierAdapter) ListAuthorizedAppGroups(ctx context.Context, userID, tenantID int64) ([]*portal.AppGroupInfo, error) {
	groups, err := a.appModule.Repo.ListGroups(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	allowed := map[int64]struct{}{}
	if a.accessSvc != nil {
		ids, err := a.accessSvc.AppsForUser(ctx, userID, tenantID)
		if err != nil {
			return nil, fmt.Errorf("apps for user: %w", err)
		}
		for _, id := range ids {
			allowed[id] = struct{}{}
		}
	}
	// Set of apps that actually surface in the card list: they exist AND are
	// enabled. The count MUST be gated by this — otherwise a rel row pointing at
	// a hard-deleted app (orphan rel whose FK cascade never fired) or a disabled
	// app inflates the sidebar number past what the list renders. Mirrors the
	// status filter in ListAuthorizedApps (status != StatusEnabled → skip).
	liveEnabled := map[int64]struct{}{}
	{
		apps, _, err := a.appModule.Repo.List(ctx, tenantID, app.ListAppParams{Page: 1, PageSize: 500})
		if err != nil {
			return nil, fmt.Errorf("list apps for group count: %w", err)
		}
		for _, ap := range apps {
			if ap.Status == app.StatusEnabled {
				liveEnabled[ap.ID] = struct{}{}
			}
		}
	}
	// Pull group → app_ids in one shot.
	type rel struct {
		GroupID int64 `gorm:"column:group_id"`
		AppID   int64 `gorm:"column:app_id"`
	}
	var rels []rel
	if len(groups) > 0 {
		groupIDs := make([]int64, len(groups))
		for i, g := range groups {
			groupIDs[i] = g.ID
		}
		if err := a.app.DB.WithContext(ctx).
			Table("mxid_app_group_rel").
			Select("group_id, app_id").
			Where("group_id IN ?", groupIDs).
			Scan(&rels).Error; err != nil {
			return nil, fmt.Errorf("load group rels: %w", err)
		}
	}
	countByGroup := map[int64]int{}
	for _, r := range rels {
		if _, ok := liveEnabled[r.AppID]; !ok {
			continue // deleted (orphan rel) or disabled app — not shown, not counted
		}
		if a.accessSvc != nil {
			if _, ok := allowed[r.AppID]; !ok {
				continue
			}
		}
		countByGroup[r.GroupID]++
	}
	out := make([]*portal.AppGroupInfo, 0, len(groups))
	for _, g := range groups {
		var parentIDStr *string
		if g.ParentID != nil {
			s := strconv.FormatInt(*g.ParentID, 10)
			parentIDStr = &s
		}
		out = append(out, &portal.AppGroupInfo{
			ID: g.ID, Name: g.Name, Code: g.Code,
			ParentID:  parentIDStr,
			SortOrder: g.SortOrder, AppCount: countByGroup[g.ID],
		})
	}
	return out, nil
}

// ListFavoriteAppIDs returns favorited app IDs in display order. We do NOT
// filter by current access policy here — if the user pinned an app and
// later lost access, the frontend simply omits it because the corresponding
// AppInfo will be absent from /apps. Keeps favorite reads cheap.
func (a *portalAppQuerierAdapter) ListFavoriteAppIDs(ctx context.Context, userID int64) ([]int64, error) {
	if a.appModule.FavRepo == nil {
		return nil, nil
	}
	return a.appModule.FavRepo.ListAppIDs(ctx, userID)
}

// AddFavorite pins an app for the user. Idempotent via repo OnConflict.
func (a *portalAppQuerierAdapter) AddFavorite(ctx context.Context, userID, tenantID, appID int64) error {
	if a.appModule.FavRepo == nil {
		return fmt.Errorf("favorites repository not wired")
	}
	return a.appModule.FavRepo.Add(ctx, &app.UserAppFavorite{
		ID: a.idGen.Generate(), TenantID: tenantID, UserID: userID, AppID: appID,
		CreatedAt: time.Now(),
	})
}

// RemoveFavorite unpins. Idempotent (no error on absent row).
func (a *portalAppQuerierAdapter) RemoveFavorite(ctx context.Context, userID, appID int64) error {
	if a.appModule.FavRepo == nil {
		return nil
	}
	return a.appModule.FavRepo.Remove(ctx, userID, appID)
}

// ReorderFavorites delegates to the repo. The repo silently skips unknown
// app_ids so racing add/remove with reorder doesn't 500.
func (a *portalAppQuerierAdapter) ReorderFavorites(ctx context.Context, userID int64, orderedAppIDs []int64) error {
	if a.appModule.FavRepo == nil {
		return fmt.Errorf("favorites repository not wired")
	}
	_, err := a.appModule.FavRepo.Reorder(ctx, userID, orderedAppIDs)
	return err
}

// ListRecentAppIDs derives recency from the audit log so we never had to
// add a dedicated launch-history table. The (actor_id, event_type,
// created_at DESC) index keeps this fast even at 10M+ audit rows.
// Returns unique app IDs in most-recent-first order, capped at `limit`.
func (a *portalAppQuerierAdapter) ListRecentAppIDs(ctx context.Context, userID, tenantID int64, limit int) ([]int64, error) {
	if limit <= 0 {
		limit = 4
	}
	if limit > 20 {
		limit = 20
	}
	// SELECT DISTINCT ON (resource_id) — Postgres keeps the first row per
	// resource_id matched in the ORDER BY, so we collapse repeat launches
	// to "last launched per app" in one pass without a window function.
	type row struct {
		AppID int64 `gorm:"column:app_id"`
	}
	var rows []row
	q := a.app.DB.WithContext(ctx).
		Raw(`
SELECT app_id FROM (
    SELECT DISTINCT ON (resource_id) resource_id AS app_id, created_at
    FROM mxid_audit_log
    WHERE tenant_id = ? AND actor_id = ? AND event_type = ?
      AND resource_type = 'app' AND resource_id IS NOT NULL
    ORDER BY resource_id, created_at DESC
) latest
ORDER BY latest.created_at DESC
LIMIT ?`, tenantID, userID, event.AppLaunched, limit)
	if err := q.Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("recent apps: %w", err)
	}
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.AppID
	}
	return ids, nil
}

func (a *portalAppQuerierAdapter) GetAppLaunchURL(ctx context.Context, appID, userID int64) (string, error) {
	ap, err := a.appModule.Repo.GetByID(ctx, appID)
	if err != nil {
		return "", err
	}
	switch ap.Protocol {
	case app.ProtocolOIDC:
		if ap.HomeURL != nil && *ap.HomeURL != "" {
			return *ap.HomeURL, nil
		}
		if ap.ClientID != nil {
			// idp_initiated=1 marks this as a portal app-list launch so /authorize
			// skips the SSO login-confirmation screen (seamless). SP-initiated
			// logins (the app sends the user to /authorize) omit it and confirm.
			return fmt.Sprintf("%s/protocol/oidc/authorize?client_id=%s&response_type=code&scope=openid+profile+email&idp_initiated=1", a.issuer, *ap.ClientID), nil
		}
	case app.ProtocolSAML:
		return fmt.Sprintf("%s/protocol/saml/%s/sso", a.issuer, ap.Code), nil
	case app.ProtocolCAS:
		if ap.LoginURL != nil {
			// idp_initiated=1 → portal launch skips the SSO confirmation (seamless).
			return fmt.Sprintf("%s/protocol/cas/%s/login?service=%s&idp_initiated=1", a.issuer, ap.Code, *ap.LoginURL), nil
		}
	}
	if ap.HomeURL != nil && *ap.HomeURL != "" {
		return *ap.HomeURL, nil
	}
	if ap.LoginURL != nil {
		return *ap.LoginURL, nil
	}
	return "", fmt.Errorf("no launch URL configured for app %d", appID)
}

func (a *portalAppQuerierAdapter) AppName(ctx context.Context, appID int64) (string, error) {
	ap, err := a.appModule.Repo.GetByID(ctx, appID)
	if err != nil {
		return "", err
	}
	return ap.Name, nil
}

/* ─────────── Session ─────────── */

type portalSessionQuerierAdapter struct{ sessionMgr *session.Manager }

func buildPortalSessionQuerier(mgr *session.Manager) portal.SessionQuerier {
	return &portalSessionQuerierAdapter{sessionMgr: mgr}
}

func (a *portalSessionQuerierAdapter) ListSessions(ctx context.Context, namespace string, userID int64) ([]*portal.SessionInfo, error) {
	sessions, err := a.sessionMgr.ListByUser(ctx, namespace, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*portal.SessionInfo, len(sessions))
	for i, s := range sessions {
		result[i] = &portal.SessionInfo{
			ID: s.ID, IP: s.IP, UserAgent: s.UserAgent, AuthType: s.AuthType,
			CreatedAt: s.CreatedAt, LastActiveAt: s.LastActiveAt,
		}
	}
	return result, nil
}

func (a *portalSessionQuerierAdapter) DeleteSession(ctx context.Context, namespace, sessionID string, userID int64) error {
	// Ownership guard: only delete the session if it belongs to the caller.
	// The id is opaque, so without this a portal user could revoke another
	// user's session by id. Not-found / not-owned is a secure no-op (no delete,
	// no info leak about whether the id exists).
	sess, err := a.sessionMgr.Get(ctx, namespace, sessionID)
	if err != nil || sess == nil || sess.UserID != userID {
		return nil
	}
	return a.sessionMgr.Delete(ctx, namespace, sessionID)
}

func (a *portalSessionQuerierAdapter) DeleteAllByUserExcept(ctx context.Context, namespace string, userID int64, exceptSID string) error {
	sessions, err := a.sessionMgr.ListByUser(ctx, namespace, userID)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if s.ID == exceptSID {
			continue
		}
		_ = a.sessionMgr.Delete(ctx, namespace, s.ID)
	}
	return nil
}

func (a *portalSessionQuerierAdapter) MarkStepUpFresh(ctx context.Context, namespace, sessionID string) error {
	return a.sessionMgr.MarkMFAVerified(ctx, namespace, sessionID)
}

/* ─────────── MFA ─────────── */

type portalMFAQuerierAdapter struct{ userModule *user.Module }

func buildPortalMFAQuerier(m *user.Module) portal.MFAQuerier {
	return &portalMFAQuerierAdapter{userModule: m}
}

func (a *portalMFAQuerierAdapter) ListMFA(ctx context.Context, userID int64) ([]*portal.MFAInfo, error) {
	mfas, err := a.userModule.Service.ListMFA(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*portal.MFAInfo, len(mfas))
	for i, m := range mfas {
		result[i] = &portal.MFAInfo{Type: m.Type, IsDefault: m.IsDefault, Verified: m.Verified}
	}
	return result, nil
}

func (a *portalMFAQuerierAdapter) SetupTOTP(ctx context.Context, userID int64) (string, string, error) {
	return a.userModule.Service.SetupTOTP(ctx, userID)
}

func (a *portalMFAQuerierAdapter) VerifyTOTP(ctx context.Context, userID int64, code string) error {
	return a.userModule.Service.VerifyTOTP(ctx, userID, code)
}

func (a *portalMFAQuerierAdapter) DeleteTOTP(ctx context.Context, userID int64) error {
	// Use service path so backup codes are wiped along with the factor.
	return a.userModule.Service.DeleteMFA(ctx, userID, "totp")
}

func (a *portalMFAQuerierAdapter) GenerateBackupCodes(ctx context.Context, userID int64) ([]string, error) {
	return a.userModule.Service.GenerateBackupCodes(ctx, userID)
}

func (a *portalMFAQuerierAdapter) CountBackupCodes(ctx context.Context, userID int64) (int, error) {
	return a.userModule.Service.CountBackupCodes(ctx, userID)
}

/* ─────────── Identity ─────────── */

type portalIdentityQuerierAdapter struct{ userModule *user.Module }

func buildPortalIdentityQuerier(m *user.Module) portal.IdentityQuerier {
	return &portalIdentityQuerierAdapter{userModule: m}
}

func (a *portalIdentityQuerierAdapter) ListIdentities(ctx context.Context, userID int64) ([]*portal.IdentityInfo, error) {
	ids, err := a.userModule.Service.ListIdentities(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*portal.IdentityInfo, len(ids))
	for i, id := range ids {
		result[i] = &portal.IdentityInfo{ProviderType: id.ProviderType, ProviderID: id.ProviderID}
		if id.ExternalName != nil {
			result[i].ExternalName = *id.ExternalName
		}
	}
	return result, nil
}

/* ─────────── API tokens ─────────── */

type portalAPITokenAdapter struct{ svc *apitoken.Service }

func buildPortalAPITokenQuerier(svc *apitoken.Service) portal.APITokenQuerier {
	return &portalAPITokenAdapter{svc: svc}
}

func (a *portalAPITokenAdapter) List(ctx context.Context, userID int64) ([]*portal.APITokenInfo, error) {
	rows, err := a.svc.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*portal.APITokenInfo, 0, len(rows))
	for _, t := range rows {
		out = append(out, toTokenInfo(t, ""))
	}
	return out, nil
}

func (a *portalAPITokenAdapter) Create(ctx context.Context, userID, tenantID int64, name string, scopes []string, expiresInDays int) (*portal.APITokenInfo, error) {
	expires := time.Duration(0)
	if expiresInDays > 0 {
		expires = time.Duration(expiresInDays) * 24 * time.Hour
	}
	res, err := a.svc.Create(ctx, apitoken.CreateInput{
		UserID: userID, TenantID: tenantID, Name: name, Scopes: scopes, ExpiresIn: expires,
	})
	if err != nil {
		return nil, err
	}
	return toTokenInfo(res.Token, res.Plaintext), nil
}

func (a *portalAPITokenAdapter) Revoke(ctx context.Context, userID, tokenID int64) error {
	return a.svc.Revoke(ctx, userID, tokenID)
}

func toTokenInfo(t *apitoken.Token, plaintext string) *portal.APITokenInfo {
	return &portal.APITokenInfo{
		ID:         t.ID,
		Name:       t.Name,
		Prefix:     t.Prefix,
		Scopes:     apitoken.ScopesOf(t),
		ExpiresAt:  t.ExpiresAt,
		LastUsedAt: t.LastUsedAt,
		RevokedAt:  t.RevokedAt,
		CreatedAt:  t.CreatedAt,
		Plaintext:  plaintext,
	}
}

/* ─────────── Login history ─────────── */

type portalLoginHistoryAdapter struct{ auditModule *audit.Module }

func buildPortalLoginHistoryQuerier(m *audit.Module) portal.LoginHistoryQuerier {
	return &portalLoginHistoryAdapter{auditModule: m}
}

// ListLoginHistory queries the audit log for the user's own login-related
// events (success/fail/logout). The audit log already retains everything
// needed; no separate table.
func (a *portalLoginHistoryAdapter) ListLoginHistory(ctx context.Context, tenantID, userID int64, limit int) ([]*portal.LoginEvent, error) {
	if a.auditModule == nil || a.auditModule.Service == nil {
		return nil, nil
	}
	uid := userID
	rows, _, err := a.auditModule.Service.List(ctx, audit.ListParams{
		TenantID: tenantID,
		Page:     1,
		PageSize: limit,
		ActorID:  &uid,
		EventTypes: []string{
			event.LoginSuccess, event.LoginFailed, event.Logout,
		},
	})
	if err != nil {
		return nil, err
	}
	out := make([]*portal.LoginEvent, 0, len(rows))
	for _, r := range rows {
		ev := &portal.LoginEvent{
			EventType: r.EventType,
			Success:   r.EventType == event.LoginSuccess || r.EventType == event.Logout,
			CreatedAt: r.CreatedAt,
		}
		if r.IP != nil {
			ev.IP = *r.IP
		}
		if r.UserAgent != nil {
			ev.UserAgent = *r.UserAgent
		}
		// Detail JSON carries the reason for failed attempts.
		if reason := extractReason(r.Detail); reason != "" {
			ev.Reason = reason
		}
		out = append(out, ev)
	}
	return out, nil
}

// extractReason pulls "reason" out of the audit detail JSONB blob without
// pulling in a full json decoder dance — best-effort, since the field is
// purely informational.
func extractReason(detail []byte) string {
	if len(detail) == 0 {
		return ""
	}
	// Cheap textual scan; the JSON is always well-formed because we
	// serialize it ourselves.
	const key = `"reason":"`
	idx := strings.Index(string(detail), key)
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	end := strings.IndexByte(string(detail)[start:], '"')
	if end < 0 {
		return ""
	}
	return string(detail)[start : start+end]
}
