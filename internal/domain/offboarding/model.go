package offboarding

import "time"

// Task / Item status + tier constants.
const (
	TaskStatusOpen     = 0 // some items still pending review
	TaskStatusResolved = 1 // every item ticked off

	ItemStatusPending = 0
	ItemStatusDone    = 1

	// Tier classifies how an app's access is revoked. L1 is cut automatically
	// by the offboard action (SSO). L2/L3 are forward-looking (SCIM auto /
	// manual-only) and refine the checklist once those land.
	TierL1 = "L1"
	TierL2 = "L2"
	TierL3 = "L3"
)

// Task is one offboarding event for a user — the parent record the console
// review panel lists.
type Task struct {
	ID             int64     `gorm:"column:id;primaryKey" json:"id,string"`
	TenantID       int64     `gorm:"column:tenant_id" json:"tenant_id,string"`
	UserID         int64     `gorm:"column:user_id" json:"user_id,string"`
	Username       string    `gorm:"column:username" json:"username"`
	Status         int       `gorm:"column:status" json:"status"`
	SessionsKilled int       `gorm:"column:sessions_killed" json:"sessions_killed"`
	ItemCount      int       `gorm:"column:item_count" json:"item_count"`
	DoneCount      int       `gorm:"column:done_count" json:"done_count"`
	CreatedBy      *int64    `gorm:"column:created_by" json:"created_by,string,omitempty"`
	CreatedAt      time.Time `gorm:"column:created_at" json:"created_at"`
}

// TableName maps Task to its table.
func (Task) TableName() string { return "mxid_offboarding_task" }

// Item is one app in a user's footprint that the admin reviews/ticks off after
// confirming downstream cleanup.
type Item struct {
	ID        int64      `gorm:"column:id;primaryKey" json:"id,string"`
	TaskID    int64      `gorm:"column:task_id" json:"task_id,string"`
	TenantID  int64      `gorm:"column:tenant_id" json:"tenant_id,string"`
	AppID     int64      `gorm:"column:app_id" json:"app_id,string"`
	AppName   string     `gorm:"column:app_name" json:"app_name"`
	AppCode   string     `gorm:"column:app_code" json:"app_code"`
	Tier      string     `gorm:"column:tier" json:"tier"`
	Status    int        `gorm:"column:status" json:"status"`
	DoneBy    *int64     `gorm:"column:done_by" json:"done_by,string,omitempty"`
	DoneAt    *time.Time `gorm:"column:done_at" json:"done_at,omitempty"`
	CreatedAt time.Time  `gorm:"column:created_at" json:"created_at"`
}

// TableName maps Item to its table.
func (Item) TableName() string { return "mxid_offboarding_item" }
