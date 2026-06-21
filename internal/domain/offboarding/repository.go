package offboarding

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// Repository persists offboarding tasks + items.
type Repository interface {
	// CreateTaskWithItems inserts the task and all its items in one transaction
	// so a review record is never half-written.
	CreateTaskWithItems(ctx context.Context, task *Task, items []*Item) error
	// ListTasks returns offboarding tasks for a tenant, newest first.
	ListTasks(ctx context.Context, tenantID int64, limit, offset int) ([]*Task, int64, error)
	// ListItems returns the items of a task (tenant-scoped).
	ListItems(ctx context.Context, tenantID, taskID int64) ([]*Item, error)
	// MarkItemDone flips an item to done, stamps who/when, and recomputes the
	// parent task's done_count / status. Returns the updated parent task id.
	MarkItemDone(ctx context.Context, tenantID, itemID, doneBy int64) (int64, error)
}

type gormRepository struct {
	db *gorm.DB
}

// NewRepository builds the gorm-backed offboarding repository.
func NewRepository(db *gorm.DB) Repository {
	return &gormRepository{db: db}
}

func (r *gormRepository) CreateTaskWithItems(ctx context.Context, task *Task, items []*Item) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(task).Error; err != nil {
			return err
		}
		if len(items) > 0 {
			if err := tx.Create(&items).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *gormRepository) ListTasks(ctx context.Context, tenantID int64, limit, offset int) ([]*Task, int64, error) {
	q := r.db.WithContext(ctx).Model(&Task{}).Where("tenant_id = ?", tenantID)
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var tasks []*Task
	if err := q.Order("created_at DESC").Limit(limit).Offset(offset).Find(&tasks).Error; err != nil {
		return nil, 0, err
	}
	return tasks, total, nil
}

func (r *gormRepository) ListItems(ctx context.Context, tenantID, taskID int64) ([]*Item, error) {
	var items []*Item
	err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND task_id = ?", tenantID, taskID).
		Order("status ASC, created_at ASC").
		Find(&items).Error
	return items, err
}

func (r *gormRepository) MarkItemDone(ctx context.Context, tenantID, itemID, doneBy int64) (int64, error) {
	var taskID int64
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var item Item
		if err := tx.Where("tenant_id = ? AND id = ?", tenantID, itemID).First(&item).Error; err != nil {
			return err
		}
		taskID = item.TaskID
		if item.Status == ItemStatusDone {
			return nil // idempotent
		}
		now := time.Now()
		if err := tx.Model(&Item{}).
			Where("id = ?", itemID).
			Updates(map[string]any{"status": ItemStatusDone, "done_by": doneBy, "done_at": now}).Error; err != nil {
			return err
		}
		// Recompute the parent task's done_count and resolved status from the
		// items, so the panel's progress badge stays accurate without a
		// separate counter that could drift.
		var done int64
		if err := tx.Model(&Item{}).Where("task_id = ? AND status = ?", taskID, ItemStatusDone).Count(&done).Error; err != nil {
			return err
		}
		var total int64
		if err := tx.Model(&Item{}).Where("task_id = ?", taskID).Count(&total).Error; err != nil {
			return err
		}
		status := TaskStatusOpen
		if total > 0 && done >= total {
			status = TaskStatusResolved
		}
		return tx.Model(&Task{}).Where("id = ?", taskID).
			Updates(map[string]any{"done_count": done, "status": status}).Error
	})
	return taskID, err
}
