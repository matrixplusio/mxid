package app

import "context"

// ListAppParams holds parameters for listing apps with filters.
type ListAppParams struct {
	Page     int
	PageSize int
	Search   string
	Protocol *string
	Status   *int
}

// Repository defines the data access interface for the application domain.
type Repository interface {
	// App CRUD
	Create(ctx context.Context, app *App) error
	GetByID(ctx context.Context, id int64) (*App, error)
	GetByIDs(ctx context.Context, ids []int64) ([]*App, error)
	GetByCode(ctx context.Context, tenantID int64, code string) (*App, error)
	GetByClientID(ctx context.Context, clientID string) (*App, error)
	Update(ctx context.Context, app *App) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context, tenantID int64, params ListAppParams) ([]*App, int64, error)
	// ListDistinctEnvs returns the distinct non-empty env labels already in use
	// by the tenant's apps (plus shared apps), so the console can offer
	// previously-typed custom envs in the dropdown instead of forcing re-entry.
	ListDistinctEnvs(ctx context.Context, tenantID int64) ([]string, error)
	UpdateStatus(ctx context.Context, id int64, status int) error
	UpdateProtocolConfig(ctx context.Context, id int64, config []byte) error

	// AppGroup CRUD
	CreateGroup(ctx context.Context, group *AppGroup) error
	GetGroupByID(ctx context.Context, id int64) (*AppGroup, error)
	UpdateGroup(ctx context.Context, group *AppGroup) error
	DeleteGroup(ctx context.Context, id int64) error
	ListGroups(ctx context.Context, tenantID int64) ([]*AppGroup, error)

	// AppGroupRel
	AddAppToGroup(ctx context.Context, rel *AppGroupRel) error
	RemoveAppFromGroup(ctx context.Context, appID, groupID int64) error
	ListAppsByGroup(ctx context.Context, groupID int64) ([]*AppGroupRel, error)

	// AppAccess
	AddAccess(ctx context.Context, access *AppAccess) error
	GetAccessByID(ctx context.Context, id int64) (*AppAccess, error)
	RemoveAccess(ctx context.Context, id int64) error
	ListAccessByApp(ctx context.Context, appID int64) ([]*AppAccess, error)

	// AppAccount
	CreateAccount(ctx context.Context, account *AppAccount) error
	GetAccountByID(ctx context.Context, id int64) (*AppAccount, error)
	UpdateAccount(ctx context.Context, account *AppAccount) error
	DeleteAccount(ctx context.Context, id int64) error

	// AppCert
	CreateCert(ctx context.Context, cert *AppCert) error
	GetCertByID(ctx context.Context, id int64) (*AppCert, error)
	ListCertsByApp(ctx context.Context, appID int64) ([]*AppCert, error)
	DeleteCert(ctx context.Context, id int64) error
}
