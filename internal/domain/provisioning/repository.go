package provisioning

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

// ErrNotFound is returned when an app has no provisioning config.
var ErrNotFound = errors.New("provisioning config not found")

// Repository persists per-app provisioning config.
type Repository interface {
	GetByApp(ctx context.Context, appID int64) (*Config, error)
	Upsert(ctx context.Context, c *Config) error
}

type gormRepository struct{ db *gorm.DB }

// NewRepository builds the gorm-backed provisioning repository.
func NewRepository(db *gorm.DB) Repository { return &gormRepository{db: db} }

func (r *gormRepository) GetByApp(ctx context.Context, appID int64) (*Config, error) {
	var c Config
	if err := r.db.WithContext(ctx).Where("app_id = ?", appID).First(&c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (r *gormRepository) Upsert(ctx context.Context, c *Config) error {
	now := time.Now()
	c.UpdatedAt = now
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	// Upsert on the app_id primary key.
	return r.db.WithContext(ctx).Save(c).Error
}
