package access

import (
	"context"
	"fmt"
	"time"

	"github.com/imkerbos/mxid/pkg/snowflake"
	"gorm.io/gorm"
)

// Repository is the raw storage layer for JIT access eligibility and requests.
type Repository interface {
	// Eligibility CRUD.
	CreateEligibility(ctx context.Context, e *Eligibility) error
	GetEligibility(ctx context.Context, id, tenantID int64) (*Eligibility, error)
	ListEligibility(ctx context.Context, tenantID int64) ([]*Eligibility, error)
	UpdateEligibility(ctx context.Context, e *Eligibility) error
	DeleteEligibility(ctx context.Context, id, tenantID int64) error

	// Request CRUD.
	CreateRequest(ctx context.Context, r *Request) error
	GetRequest(ctx context.Context, id, tenantID int64) (*Request, error)
	ListRequestsByStatus(ctx context.Context, tenantID int64, status string) ([]*Request, error)
	ListRequestsByRequester(ctx context.Context, requesterID, tenantID int64) ([]*Request, error)

	// ApproveAndGrant atomically: inserts a time-bound binding row into the
	// correct table (branching on req.TargetKind) and marks the request
	// approved with binding_id/expires_at set. Returns error if either step
	// fails (full rollback).
	ApproveAndGrant(ctx context.Context, req *Request, approverID int64, expiresAt time.Time, newBindingID int64) error

	// UpdateRequestStatus is a lightweight status transition for reject/cancel
	// flows that do not touch a binding.
	UpdateRequestStatus(ctx context.Context, id, tenantID int64, status, reason string, approverID *int64) error

	// EndGrant atomically hard-deletes the binding row from the correct table
	// and transitions the request to finalStatus (revoked or expired).
	EndGrant(ctx context.Context, req *Request, finalStatus string, bindingStatus int) error

	// ListDueGrants returns approved requests whose expires_at <= NOW().
	// The sweeper uses this list to call EndGrant on each entry.
	ListDueGrants(ctx context.Context) ([]*Request, error)
}

type repo struct {
	db    *gorm.DB
	idGen *snowflake.Generator
}

// NewRepository constructs a Repository backed by db.
func NewRepository(db *gorm.DB, idGen *snowflake.Generator) Repository {
	return &repo{db: db, idGen: idGen}
}

// ─── Eligibility ──────────────────────────────────────────────────────────────

func (r *repo) CreateEligibility(ctx context.Context, e *Eligibility) error {
	return r.db.WithContext(ctx).Create(e).Error
}

func (r *repo) GetEligibility(ctx context.Context, id, tenantID int64) (*Eligibility, error) {
	var e Eligibility
	err := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		First(&e).Error
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (r *repo) ListEligibility(ctx context.Context, tenantID int64) ([]*Eligibility, error) {
	var rows []*Eligibility
	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	// Console (and portal) eligibility lists show target/requester/approver by
	// name, not a raw snowflake id. Best-effort: a lookup failure must not
	// fail the list — the name is cosmetic display only, the id columns
	// remain authoritative.
	r.populateEligibilityNames(ctx, rows)
	return rows, nil
}

// populateEligibilityNames resolves the four cosmetic *Name fields on each
// Eligibility row. Batches one query per distinct backing table rather than
// N+1 per row — dedup ids first, then a single `IN (...)` per table.
//
// Table notes (verified against migrations 000003/000004/000006/000026):
//   - mxid_role, mxid_app, mxid_user_group, mxid_organization all soft-delete
//     via deleted_at — filtered out so a deleted row's stale name never leaks.
//   - mxid_app_role has no deleted_at column (hard-delete only) — no filter.
//   - mxid_user resolution mirrors populateRequesterNames's
//     display_name-with-username-fallback rule (batchUserNames).
func (r *repo) populateEligibilityNames(ctx context.Context, rows []*Eligibility) {
	if len(rows) == 0 {
		return
	}

	var roleIDs, appRoleIDs, appIDs, groupIDs, orgIDs, userIDs []int64
	seenRole := map[int64]bool{}
	seenAppRole := map[int64]bool{}
	seenApp := map[int64]bool{}
	seenGroup := map[int64]bool{}
	seenOrg := map[int64]bool{}
	seenUser := map[int64]bool{}

	add := func(dst *[]int64, seen map[int64]bool, id int64) {
		if id == 0 || seen[id] {
			return
		}
		seen[id] = true
		*dst = append(*dst, id)
	}

	for _, e := range rows {
		switch e.TargetKind {
		case TargetConsole:
			add(&roleIDs, seenRole, e.RoleID)
		case TargetApp:
			add(&appRoleIDs, seenAppRole, e.RoleID)
			if e.AppID != nil {
				add(&appIDs, seenApp, *e.AppID)
			}
		}
		switch e.RequesterSubjectType {
		case "user":
			add(&userIDs, seenUser, e.RequesterSubjectID)
		case "group":
			add(&groupIDs, seenGroup, e.RequesterSubjectID)
		case "org":
			add(&orgIDs, seenOrg, e.RequesterSubjectID)
		}
		switch e.ApproverSubjectType {
		case ApproverRole:
			add(&roleIDs, seenRole, e.ApproverSubjectID)
		case ApproverGroup:
			add(&groupIDs, seenGroup, e.ApproverSubjectID)
		case ApproverUser:
			add(&userIDs, seenUser, e.ApproverSubjectID)
		}
	}

	roleNames := r.batchNames(ctx, "mxid_role", roleIDs, true)
	appRoleNames := r.batchNames(ctx, "mxid_app_role", appRoleIDs, false)
	appNames := r.batchNames(ctx, "mxid_app", appIDs, true)
	groupNames := r.batchNames(ctx, "mxid_user_group", groupIDs, true)
	orgNames := r.batchNames(ctx, "mxid_organization", orgIDs, true)
	userNames := r.batchUserNames(ctx, userIDs)

	for _, e := range rows {
		switch e.TargetKind {
		case TargetConsole:
			e.TargetName = roleNames[e.RoleID]
		case TargetApp:
			e.TargetName = appRoleNames[e.RoleID]
			if e.AppID != nil {
				e.AppName = appNames[*e.AppID]
			}
		}
		switch e.RequesterSubjectType {
		case "user":
			e.RequesterSubjectName = userNames[e.RequesterSubjectID]
		case "group":
			e.RequesterSubjectName = groupNames[e.RequesterSubjectID]
		case "org":
			e.RequesterSubjectName = orgNames[e.RequesterSubjectID]
			// case "any": leave empty — frontend renders "Everyone".
		}
		switch e.ApproverSubjectType {
		case ApproverRole:
			e.ApproverSubjectName = roleNames[e.ApproverSubjectID]
		case ApproverGroup:
			e.ApproverSubjectName = groupNames[e.ApproverSubjectID]
		case ApproverUser:
			e.ApproverSubjectName = userNames[e.ApproverSubjectID]
			// case "auto": leave empty — frontend renders "Auto".
		}
	}
}

// batchNames looks up `name` for the given ids from table in one query,
// returning an id->name map. filterDeleted adds `AND deleted_at IS NULL` for
// tables that soft-delete (mxid_app_role does not have this column).
// A query error or empty ids returns a nil map (callers get "" on lookup).
func (r *repo) batchNames(ctx context.Context, table string, ids []int64, filterDeleted bool) map[int64]string {
	if len(ids) == 0 {
		return nil
	}
	var out []struct {
		ID   int64
		Name string
	}
	q := r.db.WithContext(ctx).Table(table).Select("id, name").Where("id IN ?", ids)
	if filterDeleted {
		q = q.Where("deleted_at IS NULL")
	}
	if err := q.Find(&out).Error; err != nil {
		return nil
	}
	m := make(map[int64]string, len(out))
	for _, row := range out {
		m[row.ID] = row.Name
	}
	return m
}

// batchUserNames resolves display_name (falling back to username) for the
// given mxid_user ids in one query. Shared by populateEligibilityNames and
// populateRequesterNames so the fallback rule stays in one place.
func (r *repo) batchUserNames(ctx context.Context, ids []int64) map[int64]string {
	if len(ids) == 0 {
		return nil
	}
	var users []struct {
		ID          int64
		DisplayName *string
		Username    string
	}
	if err := r.db.WithContext(ctx).
		Table("mxid_user").
		Select("id, display_name, username").
		Where("id IN ?", ids).
		Find(&users).Error; err != nil {
		return nil
	}
	m := make(map[int64]string, len(users))
	for _, u := range users {
		if u.DisplayName != nil && *u.DisplayName != "" {
			m[u.ID] = *u.DisplayName
		} else {
			m[u.ID] = u.Username
		}
	}
	return m
}

// UpdateEligibility overwrites the editable columns of an existing
// eligibility row, scoped by (id, tenant_id) so a caller can never update
// another tenant's row. Uses an explicit Select so GORM includes zero-valued
// fields (e.g. require_justification:false) in the UPDATE — the same
// footgun documented on Eligibility.RequireJustification/RequireStepUp
// applies to Updates() with a bare struct, not just Create().
func (r *repo) UpdateEligibility(ctx context.Context, e *Eligibility) error {
	e.UpdatedAt = time.Now()
	return r.db.WithContext(ctx).
		Model(&Eligibility{}).
		Where("id = ? AND tenant_id = ?", e.ID, e.TenantID).
		Select(
			"target_kind", "role_id", "scope_type", "scope_id", "app_id",
			"requester_subject_type", "requester_subject_id",
			"allowed_durations", "max_duration_seconds",
			"approver_subject_type", "approver_subject_id",
			"require_justification", "require_stepup", "updated_at",
		).
		Updates(e).Error
}

func (r *repo) DeleteEligibility(ctx context.Context, id, tenantID int64) error {
	return r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		Delete(&Eligibility{}).Error
}

// ─── Request ──────────────────────────────────────────────────────────────────

func (r *repo) CreateRequest(ctx context.Context, req *Request) error {
	return r.db.WithContext(ctx).Create(req).Error
}

func (r *repo) GetRequest(ctx context.Context, id, tenantID int64) (*Request, error) {
	var req Request
	err := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", id, tenantID).
		First(&req).Error
	if err != nil {
		return nil, err
	}
	return &req, nil
}

func (r *repo) ListRequestsByStatus(ctx context.Context, tenantID int64, status string) ([]*Request, error) {
	var rows []*Request
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND status = ?", tenantID, status).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	// Console approvals list shows the requester by name, not a raw snowflake
	// id. Best-effort: a lookup failure must not fail the list — the name is
	// cosmetic display only, the id remains authoritative in requester_id.
	r.populateRequesterNames(ctx, rows)
	return rows, nil
}

// populateRequesterNames looks up each row's requester display_name
// (falling back to username when unset) and fills Request.RequesterName.
//
// This is a single extra batched lookup rather than a literal SQL LEFT JOIN
// on mxid_access_request, deliberately: Request.RequesterName is fully
// ignored by GORM (gorm:"-") so every other query against this model stays a
// plain, unaffected `SELECT <request columns>`. Making GORM populate an
// ignored field from a joined column would require either abandoning the
// shared Request model for this one query (a parallel struct to keep in sync
// with every future request-table migration) or hand-writing the full
// request column list in raw SQL (the same brittleness). A second indexed
// query by primary key is simpler and safe at console list sizes.
func (r *repo) populateRequesterNames(ctx context.Context, rows []*Request) {
	if len(rows) == 0 {
		return
	}
	seen := make(map[int64]bool, len(rows))
	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		if !seen[row.RequesterID] {
			seen[row.RequesterID] = true
			ids = append(ids, row.RequesterID)
		}
	}

	names := r.batchUserNames(ctx, ids)
	for _, row := range rows {
		row.RequesterName = names[row.RequesterID]
	}
}

func (r *repo) ListRequestsByRequester(ctx context.Context, requesterID, tenantID int64) ([]*Request, error) {
	var rows []*Request
	err := r.db.WithContext(ctx).
		Where("requester_id = ? AND tenant_id = ?", requesterID, tenantID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

// ─── Grant operations ─────────────────────────────────────────────────────────

// bindingTable returns the backing table name for the given target kind.
func (r *repo) bindingTable(kind string) string {
	if kind == TargetApp {
		return "mxid_app_role_binding"
	}
	return "mxid_role_binding"
}

// insertBindingTx inserts the time-bound binding inside tx.
//
// mxid_role_binding columns (verified, migration 000006 + 000016 + 000045):
//
//	id, role_id, subject_type, subject_id, scope_type, scope_id,
//	grant_id, expires_at, status, created_at
//
// mxid_app_role_binding columns (verified, migration 000026 + 000027 + 000045):
//
//	id, app_id, tenant_id, app_role_id, subject_type, subject_id,
//	app_group_id (nullable), grant_id, expires_at, status, created_at, created_by
//
// For the app binding we omit app_group_id so the CHECK constraint
// (app_id IS NOT NULL AND app_group_id IS NULL) is satisfied.
func (r *repo) insertBindingTx(tx *gorm.DB, req *Request, bindingID int64, expiresAt time.Time) error {
	switch req.TargetKind {
	case TargetConsole:
		return tx.Exec(`
INSERT INTO mxid_role_binding
    (id, role_id, subject_type, subject_id, scope_type, scope_id, grant_id, expires_at, status, created_at)
VALUES (?, ?, 'user', ?, ?, ?, ?, ?, ?, NOW())`,
			bindingID,
			req.RoleID,
			req.RequesterID,
			req.ScopeType,
			req.ScopeID,
			req.ID,
			expiresAt,
			BindingActive,
		).Error

	case TargetApp:
		if req.AppID == nil {
			return fmt.Errorf("access: app_id is required for TargetApp grant")
		}
		return tx.Exec(`
INSERT INTO mxid_app_role_binding
    (id, app_id, app_role_id, subject_type, subject_id, tenant_id, grant_id, expires_at, status, created_at)
VALUES (?, ?, ?, 'user', ?, ?, ?, ?, ?, NOW())`,
			bindingID,
			*req.AppID,
			req.RoleID,
			req.RequesterID,
			req.TenantID,
			req.ID,
			expiresAt,
			BindingActive,
		).Error

	default:
		return fmt.Errorf("access: unknown target_kind %q", req.TargetKind)
	}
}

// ApproveAndGrant runs in ONE transaction:
//  1. INSERT the time-bound binding row.
//  2. UPDATE the request to approved with binding_id/expires_at/activated_at/decided_at.
//
// All three request-row timestamps (decided_at, activated_at, updated_at) use
// the same Go-side `now` instant rather than mixing it with a DB-side NOW() —
// under DB clock skew or a slow-running transaction the two could otherwise
// disagree within the same row.
func (r *repo) ApproveAndGrant(ctx context.Context, req *Request, approverID int64, expiresAt time.Time, newBindingID int64) error {
	now := time.Now()
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := r.insertBindingTx(tx, req, newBindingID, expiresAt); err != nil {
			return err
		}
		return tx.Exec(`
UPDATE mxid_access_request
SET status = ?, approver_id = ?, decided_at = ?, activated_at = ?, expires_at = ?, binding_id = ?, updated_at = ?
WHERE id = ? AND tenant_id = ? AND status = ?`,
			StatusApproved,
			approverID,
			now,
			now,
			expiresAt,
			newBindingID,
			now,
			req.ID,
			req.TenantID,
			StatusPending,
		).Error
	})
}

// UpdateRequestStatus is a lightweight transition for reject/cancel flows that
// do not involve a binding (no tx needed).
func (r *repo) UpdateRequestStatus(ctx context.Context, id, tenantID int64, status, reason string, approverID *int64) error {
	return r.db.WithContext(ctx).Exec(`
UPDATE mxid_access_request
SET status = ?, decision_reason = ?, approver_id = COALESCE(?, approver_id), decided_at = NOW(), updated_at = NOW()
WHERE id = ? AND tenant_id = ?`,
		status, reason, approverID, id, tenantID,
	).Error
}

// EndGrant runs in ONE transaction:
//  1. Hard-DELETE the binding row from the correct table.
//  2. UPDATE the request to finalStatus.
func (r *repo) EndGrant(ctx context.Context, req *Request, finalStatus string, bindingStatus int) error {
	// bindingStatus is ignored under the current hard-delete strategy; retained for a future soft-delete path.
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if req.BindingID != nil {
			table := r.bindingTable(req.TargetKind)
			// Use Sprintf for table name — safe because bindingTable only ever
			// returns one of two hard-coded strings; no user input reaches here.
			if err := tx.Exec(
				fmt.Sprintf("DELETE FROM %s WHERE id = ?", table), //nolint:gosec
				*req.BindingID,
			).Error; err != nil {
				return err
			}
		}
		return tx.Exec(`
UPDATE mxid_access_request SET status = ?, updated_at = NOW()
WHERE id = ? AND tenant_id = ?`,
			finalStatus, req.ID, req.TenantID,
		).Error
	})
}

// ListDueGrants returns approved requests whose expires_at <= NOW().
// The sweeper calls EndGrant on each.
func (r *repo) ListDueGrants(ctx context.Context) ([]*Request, error) {
	var rows []*Request
	err := r.db.WithContext(ctx).
		Where("status = ? AND expires_at IS NOT NULL AND expires_at <= NOW()", StatusApproved).
		Find(&rows).Error
	return rows, err
}
