package app

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// gormRepository implements Repository using GORM.
type gormRepository struct {
	db *gorm.DB
}

// NewGormRepository creates a new GORM-based app repository.
func NewGormRepository(db *gorm.DB) Repository {
	return &gormRepository{db: db}
}

// --- App CRUD ---

// Create inserts a new app record.
func (r *gormRepository) Create(ctx context.Context, app *App) error {
	if err := r.db.WithContext(ctx).Create(app).Error; err != nil {
		return fmt.Errorf("create app: %w", err)
	}
	return nil
}

// GetByIDs loads multiple apps in a single query.
func (r *gormRepository) GetByIDs(ctx context.Context, ids []int64) ([]*App, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var apps []*App
	err := r.db.WithContext(ctx).Where("id IN ?", ids).Find(&apps).Error
	if err != nil {
		return nil, fmt.Errorf("get apps by ids: %w", err)
	}
	return apps, nil
}

// GetByID finds an app by primary key.
func (r *gormRepository) GetByID(ctx context.Context, id int64) (*App, error) {
	var app App
	if err := r.db.WithContext(ctx).First(&app, id).Error; err != nil {
		return nil, fmt.Errorf("get app by id: %w", err)
	}
	return &app, nil
}

// GetByCode finds an app by tenant and code.
func (r *gormRepository) GetByCode(ctx context.Context, tenantID int64, code string) (*App, error) {
	var app App
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND code = ?", tenantID, code).
		First(&app).Error
	if err != nil {
		return nil, fmt.Errorf("get app by code: %w", err)
	}
	return &app, nil
}

// GetByClientID finds an app by client_id.
func (r *gormRepository) GetByClientID(ctx context.Context, clientID string) (*App, error) {
	var app App
	err := r.db.WithContext(ctx).
		Where("client_id = ?", clientID).
		First(&app).Error
	if err != nil {
		return nil, fmt.Errorf("get app by client_id: %w", err)
	}
	return &app, nil
}

// Update saves changes to an existing app.
func (r *gormRepository) Update(ctx context.Context, app *App) error {
	if err := r.db.WithContext(ctx).Save(app).Error; err != nil {
		return fmt.Errorf("update app: %w", err)
	}
	return nil
}

// Delete performs a soft delete on an app.
// Delete HARD-deletes the app. Config entities are not soft-deleted: the schema
// carries ON DELETE CASCADE on every child (app_group_rel, app_access, app_cert,
// app_account, consents, favorites), and those cascades only fire on a physical
// delete. A soft delete (deleted_at) leaves the row alive from the FK's view and
// strands every association as an orphan — the root cause of the "deleted app
// still shows in its group" and access-policy "(未知)" bugs. Policy rows (no FK,
// migration 000056 adds app_id/app_group_id FK CASCADE) go with it too.
func (r *gormRepository) Delete(ctx context.Context, id int64) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&App{}, id).Error; err != nil {
		return fmt.Errorf("delete app: %w", err)
	}
	return nil
}

// List returns a paginated list of apps with optional filters.
//
// Includes BOTH:
//   - tenant-scoped apps belonging to `tenantID` (Scope=1, tenant_id matches)
//   - shared apps visible globally (Scope=2, tenant_id IS NULL)
//
// Shared apps surface in every tenant's catalogue so a SaaS application
// configured once by super_admin appears for all tenants. Each tenant still
// controls who can access via mxid_app_access (per-tenant ACL).
func (r *gormRepository) List(ctx context.Context, tenantID int64, params ListAppParams) ([]*App, int64, error) {
	var apps []*App
	var total int64

	query := r.db.WithContext(ctx).Model(&App{}).
		Where("tenant_id = ? OR scope = ?", tenantID, ScopeShared)

	query = query.Scopes(
		appSearchScope(params.Search),
		appProtocolScope(params.Protocol),
		appStatusScope(params.Status),
	)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count apps: %w", err)
	}

	offset := (params.Page - 1) * params.PageSize
	if err := query.Offset(offset).Limit(params.PageSize).Order("created_at DESC").Find(&apps).Error; err != nil {
		return nil, 0, fmt.Errorf("list apps: %w", err)
	}

	return apps, total, nil
}

// ListDistinctEnvs returns the distinct non-empty env labels used by the
// tenant's own + shared apps, alphabetically. Mirrors List's tenant/shared
// visibility so the dropdown never leaks another tenant's env names.
func (r *gormRepository) ListDistinctEnvs(ctx context.Context, tenantID int64) ([]string, error) {
	var envs []string
	if err := r.db.WithContext(ctx).Model(&App{}).
		Where("(tenant_id = ? OR scope = ?) AND env IS NOT NULL AND env <> ''", tenantID, ScopeShared).
		Distinct().
		Order("env").
		Pluck("env", &envs).Error; err != nil {
		return nil, fmt.Errorf("list distinct envs: %w", err)
	}
	return envs, nil
}

// UpdateStatus updates only the status field of an app.
func (r *gormRepository) UpdateStatus(ctx context.Context, id int64, status int) error {
	result := r.db.WithContext(ctx).
		Model(&App{}).
		Where("id = ?", id).
		Update("status", status)
	if result.Error != nil {
		return fmt.Errorf("update app status: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// UpdateProtocolConfig updates only the protocol_config field of an app.
func (r *gormRepository) UpdateProtocolConfig(ctx context.Context, id int64, config []byte) error {
	result := r.db.WithContext(ctx).
		Model(&App{}).
		Where("id = ?", id).
		Update("protocol_config", gorm.Expr("?::jsonb", string(config)))
	if result.Error != nil {
		return fmt.Errorf("update protocol config: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// --- Scopes ---

// appSearchScope filters by name/code/description. The WHERE expression
// matches the GIN trgm index created in migration 000030 so the planner
// uses the index for substring matches even on large tables.
func appSearchScope(search string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if search == "" {
			return db
		}
		like := "%" + strings.ToLower(search) + "%"
		return db.Where("(lower(name) || ' ' || lower(code) || ' ' || lower(coalesce(description, ''))) LIKE ?", like)
	}
}

func appProtocolScope(protocol *string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if protocol == nil {
			return db
		}
		return db.Where("protocol = ?", *protocol)
	}
}

func appStatusScope(status *int) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if status == nil {
			return db
		}
		return db.Where("status = ?", *status)
	}
}

// --- AppGroup CRUD ---

// CreateGroup inserts a new app group record.
func (r *gormRepository) CreateGroup(ctx context.Context, group *AppGroup) error {
	if err := r.db.WithContext(ctx).Create(group).Error; err != nil {
		return fmt.Errorf("create app group: %w", err)
	}
	return nil
}

// GetGroupByID finds an app group by primary key.
func (r *gormRepository) GetGroupByID(ctx context.Context, id int64) (*AppGroup, error) {
	var group AppGroup
	if err := r.db.WithContext(ctx).First(&group, id).Error; err != nil {
		return nil, fmt.Errorf("get app group by id: %w", err)
	}
	return &group, nil
}

// UpdateGroup saves changes to an existing app group.
func (r *gormRepository) UpdateGroup(ctx context.Context, group *AppGroup) error {
	if err := r.db.WithContext(ctx).Save(group).Error; err != nil {
		return fmt.Errorf("update app group: %w", err)
	}
	return nil
}

// DeleteGroup performs a soft delete on an app group.
// DeleteGroup HARD-deletes the app group so its app_group_rel links cascade away
// and nested groups' parent_id is SET NULL. Soft delete would orphan both. The
// group's inherited access policies (app_group_id, no FK before migration 000056)
// cascade via that new FK.
func (r *gormRepository) DeleteGroup(ctx context.Context, id int64) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&AppGroup{}, id).Error; err != nil {
		return fmt.Errorf("delete app group: %w", err)
	}
	return nil
}

// ListGroups returns all app groups for a tenant ordered by sort_order.
func (r *gormRepository) ListGroups(ctx context.Context, tenantID int64) ([]*AppGroup, error) {
	var groups []*AppGroup
	err := r.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		Order("sort_order ASC, created_at ASC").
		Find(&groups).Error
	if err != nil {
		return nil, fmt.Errorf("list app groups: %w", err)
	}
	return groups, nil
}

// --- AppGroupRel ---

// AddAppToGroup inserts a new app-group relation. Uses ON CONFLICT
// DO NOTHING so re-adding an existing membership is a no-op (idempotent) —
// admins double-clicking the button shouldn't get a 500 from the unique
// constraint on (app_id, group_id).
func (r *gormRepository) AddAppToGroup(ctx context.Context, rel *AppGroupRel) error {
	if err := r.db.WithContext(ctx).Exec(`
		INSERT INTO mxid_app_group_rel (id, app_id, group_id, created_at)
		VALUES (?, ?, ?, NOW())
		ON CONFLICT (app_id, group_id) DO NOTHING
	`, rel.ID, rel.AppID, rel.GroupID).Error; err != nil {
		return fmt.Errorf("add app to group: %w", err)
	}
	return nil
}

// RemoveAppFromGroup deletes an app-group relation.
func (r *gormRepository) RemoveAppFromGroup(ctx context.Context, appID, groupID int64) error {
	result := r.db.WithContext(ctx).
		Where("app_id = ? AND group_id = ?", appID, groupID).
		Delete(&AppGroupRel{})
	if result.Error != nil {
		return fmt.Errorf("remove app from group: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListAppsByGroup returns all app-group relations for a given group.
func (r *gormRepository) ListAppsByGroup(ctx context.Context, groupID int64) ([]*AppGroupRel, error) {
	var rels []*AppGroupRel
	err := r.db.WithContext(ctx).
		Where("group_id = ?", groupID).
		Order("created_at DESC").
		Find(&rels).Error
	if err != nil {
		return nil, fmt.Errorf("list apps by group: %w", err)
	}
	return rels, nil
}

// --- AppAccess ---

// AddAccess inserts a new access authorization.
func (r *gormRepository) AddAccess(ctx context.Context, access *AppAccess) error {
	if err := r.db.WithContext(ctx).Create(access).Error; err != nil {
		return fmt.Errorf("add access: %w", err)
	}
	return nil
}

// GetAccessByID finds an access authorization by primary key. The row carries
// no tenant_id; callers derive tenancy via the parent app (AppID) and must run
// the tenant-scoped app GetByID before acting on it.
func (r *gormRepository) GetAccessByID(ctx context.Context, id int64) (*AppAccess, error) {
	var access AppAccess
	if err := r.db.WithContext(ctx).First(&access, id).Error; err != nil {
		return nil, err
	}
	return &access, nil
}

// RemoveAccess deletes an access authorization by ID.
func (r *gormRepository) RemoveAccess(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Delete(&AppAccess{}, id)
	if result.Error != nil {
		return fmt.Errorf("remove access: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListAccessByApp returns all access authorizations for an app.
func (r *gormRepository) ListAccessByApp(ctx context.Context, appID int64) ([]*AppAccess, error) {
	var accesses []*AppAccess
	err := r.db.WithContext(ctx).
		Where("app_id = ?", appID).
		Order("created_at DESC").
		Find(&accesses).Error
	if err != nil {
		return nil, fmt.Errorf("list access by app: %w", err)
	}
	return accesses, nil
}

// --- AppAccount ---

// CreateAccount inserts a new app account record.
func (r *gormRepository) CreateAccount(ctx context.Context, account *AppAccount) error {
	if err := r.db.WithContext(ctx).Create(account).Error; err != nil {
		return fmt.Errorf("create app account: %w", err)
	}
	return nil
}

// GetAccountByID finds an app account by primary key.
func (r *gormRepository) GetAccountByID(ctx context.Context, id int64) (*AppAccount, error) {
	var account AppAccount
	if err := r.db.WithContext(ctx).First(&account, id).Error; err != nil {
		return nil, fmt.Errorf("get app account by id: %w", err)
	}
	return &account, nil
}

// UpdateAccount saves changes to an existing app account.
func (r *gormRepository) UpdateAccount(ctx context.Context, account *AppAccount) error {
	if err := r.db.WithContext(ctx).Save(account).Error; err != nil {
		return fmt.Errorf("update app account: %w", err)
	}
	return nil
}

// DeleteAccount deletes an app account by ID.
func (r *gormRepository) DeleteAccount(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Delete(&AppAccount{}, id)
	if result.Error != nil {
		return fmt.Errorf("delete app account: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// --- AppCert ---

// CreateCert inserts a new app certificate record.
func (r *gormRepository) CreateCert(ctx context.Context, cert *AppCert) error {
	if err := r.db.WithContext(ctx).Create(cert).Error; err != nil {
		return fmt.Errorf("create app cert: %w", err)
	}
	return nil
}

// ListCertsByApp returns all certificates for an app.
func (r *gormRepository) ListCertsByApp(ctx context.Context, appID int64) ([]*AppCert, error) {
	var certs []*AppCert
	err := r.db.WithContext(ctx).
		Where("app_id = ?", appID).
		Order("created_at DESC").
		Find(&certs).Error
	if err != nil {
		return nil, fmt.Errorf("list app certs: %w", err)
	}
	return certs, nil
}

// GetCertByID finds an app certificate by primary key. The row carries no
// tenant_id; callers derive tenancy via the parent app (AppID) and must run the
// tenant-scoped app GetByID before acting on it.
func (r *gormRepository) GetCertByID(ctx context.Context, id int64) (*AppCert, error) {
	var cert AppCert
	if err := r.db.WithContext(ctx).First(&cert, id).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}

// DeleteCert deletes an app certificate by ID.
func (r *gormRepository) DeleteCert(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Delete(&AppCert{}, id)
	if result.Error != nil {
		return fmt.Errorf("delete app cert: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
