package conditionalaccess

import (
	"context"
	"time"
)

// KnownDevice is a device recognised for a user (storage row, mxid_known_device).
type KnownDevice struct {
	ID          int64     `gorm:"column:id;primaryKey" json:"id"`
	TenantID    int64     `gorm:"column:tenant_id;not null" json:"tenant_id"`
	UserID      int64     `gorm:"column:user_id;not null" json:"user_id"`
	DeviceID    string    `gorm:"column:device_id;not null;size:64" json:"device_id"`
	UserAgent   string    `gorm:"column:user_agent;size:512" json:"user_agent"`
	FirstSeenAt time.Time `gorm:"column:first_seen_at;not null" json:"first_seen_at"`
	LastSeenAt  time.Time `gorm:"column:last_seen_at;not null" json:"last_seen_at"`
}

// TableName binds to the migration's table name.
func (KnownDevice) TableName() string { return "mxid_known_device" }

// AuditResource implements audit.Audited.
func (KnownDevice) AuditResource() string { return "known_device" }

// TenantScoped marks mxid_known_device for automatic tenant isolation.
func (KnownDevice) TenantScoped() {}

// DeviceRepo persists known devices. Get returns (nil, nil) when absent.
type DeviceRepo interface {
	Get(ctx context.Context, userID int64, deviceID string) (*KnownDevice, error)
	Insert(ctx context.Context, d *KnownDevice) error
	TouchLastSeen(ctx context.Context, id int64, at time.Time) error
}

// IDGen mints snowflake ids for new device rows.
type IDGen interface{ Generate() int64 }

// DeviceService answers "is this a known device?" and registers devices after a
// successful login. The HTTP layer owns the mxid_device_id cookie; this owns
// the database truth.
type DeviceService struct {
	repo  DeviceRepo
	idgen IDGen
	now   func() time.Time
}

// NewDeviceService wires a device service. now defaults to time.Now.
func NewDeviceService(repo DeviceRepo, idgen IDGen) *DeviceService {
	return &DeviceService{repo: repo, idgen: idgen, now: time.Now}
}

// IsKnown reports whether deviceID is recognised for the user. An empty
// deviceID (no cookie) is never known — i.e. a new-device signal.
func (s *DeviceService) IsKnown(ctx context.Context, userID int64, deviceID string) (bool, error) {
	if deviceID == "" {
		return false, nil
	}
	d, err := s.repo.Get(ctx, userID, deviceID)
	if err != nil {
		return false, err
	}
	return d != nil, nil
}

// Remember records the device for the user after a successful authentication:
// refreshes last_seen on a known device, inserts a row for a new one. The
// caller passes the (possibly freshly-minted) deviceID it set in the cookie.
// An empty deviceID is a no-op.
func (s *DeviceService) Remember(ctx context.Context, tenantID, userID int64, deviceID, userAgent string) error {
	if deviceID == "" {
		return nil
	}
	existing, err := s.repo.Get(ctx, userID, deviceID)
	if err != nil {
		return err
	}
	now := s.now()
	if existing != nil {
		return s.repo.TouchLastSeen(ctx, existing.ID, now)
	}
	return s.repo.Insert(ctx, &KnownDevice{
		ID:          s.idgen.Generate(),
		TenantID:    tenantID,
		UserID:      userID,
		DeviceID:    deviceID,
		UserAgent:   userAgent,
		FirstSeenAt: now,
		LastSeenAt:  now,
	})
}
