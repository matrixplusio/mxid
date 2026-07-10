package group

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// liveGroupMember restricts a mxid_user_group_member query to members whose user
// is not soft-deleted. The member LIST already INNER JOINs mxid_user with the
// same predicate; the COUNT paths did not, so a soft-deleted user (whose
// membership row lingers until the UserDeleted purge) inflated the count and
// desynced it from the returned page. Defense-in-depth for a dropped event.
const liveGroupMember = "user_id IN (SELECT id FROM mxid_user WHERE deleted_at IS NULL)"

type repository struct {
	db *gorm.DB
}

// NewRepository creates a new GORM-backed user group repository.
func NewRepository(db *gorm.DB) Repository {
	return &repository{db: db}
}

func (r *repository) Create(ctx context.Context, g *UserGroup) error {
	if err := r.db.WithContext(ctx).Create(g).Error; err != nil {
		return fmt.Errorf("create user group: %w", err)
	}
	return nil
}

func (r *repository) GetByID(ctx context.Context, id int64) (*UserGroup, error) {
	var g UserGroup
	if err := r.db.WithContext(ctx).First(&g, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("get user group by id: %w", err)
	}
	return &g, nil
}

func (r *repository) Update(ctx context.Context, g *UserGroup) error {
	if err := r.db.WithContext(ctx).Save(g).Error; err != nil {
		return fmt.Errorf("update user group: %w", err)
	}
	return nil
}

// Delete HARD-deletes the user group so its members (mxid_user_group_member) and
// dynamic rule (mxid_user_group_rule) cascade away. Soft delete leaves both as
// orphans. The group's access policies (subject_type='group', polymorphic
// subject_id has no FK) are removed by the GroupDeleted event subscriber.
func (r *repository) Delete(ctx context.Context, id int64) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&UserGroup{}, "id = ?", id).Error; err != nil {
		return fmt.Errorf("delete user group: %w", err)
	}
	return nil
}

func (r *repository) List(ctx context.Context, tenantID int64, keyword string, page, pageSize int) ([]*UserGroup, int64, error) {
	q := r.db.WithContext(ctx).Model(&UserGroup{}).Where("tenant_id = ?", tenantID)
	if keyword != "" {
		// ILIKE is Postgres-specific; the project pins Postgres so this is safe.
		// % wrapping is done with a placeholder so user input is escaped.
		like := "%" + keyword + "%"
		q = q.Where("name ILIKE ? OR code ILIKE ? OR description ILIKE ?", like, like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count user groups: %w", err)
	}

	groups := make([]*UserGroup, 0, pageSize)
	offset := (page - 1) * pageSize
	if err := q.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&groups).Error; err != nil {
		return nil, 0, fmt.Errorf("list user groups: %w", err)
	}
	return groups, total, nil
}

func (r *repository) ListDynamicGroupIDs(ctx context.Context, tenantID int64) ([]int64, error) {
	ids := make([]int64, 0)
	if err := r.db.WithContext(ctx).
		Model(&UserGroup{}).
		Where("tenant_id = ? AND type = ?", tenantID, TypeDynamic).
		Pluck("id", &ids).Error; err != nil {
		return nil, fmt.Errorf("list dynamic group ids: %w", err)
	}
	return ids, nil
}

func (r *repository) ListByUserID(ctx context.Context, tenantID, userID int64) ([]*UserGroup, error) {
	groups := make([]*UserGroup, 0)
	err := r.db.WithContext(ctx).
		Model(&UserGroup{}).
		Joins("INNER JOIN mxid_user_group_member m ON m.group_id = mxid_user_group.id").
		Where("m.user_id = ? AND mxid_user_group.tenant_id = ? AND mxid_user_group.deleted_at IS NULL", userID, tenantID).
		Order("mxid_user_group.created_at DESC").
		Find(&groups).Error
	if err != nil {
		return nil, fmt.Errorf("list groups by user: %w", err)
	}
	return groups, nil
}

func (r *repository) AddMember(ctx context.Context, m *UserGroupMember) error {
	// ON CONFLICT DO NOTHING so duplicate (group_id, user_id) is silently a no-op
	// — keeps single-add idempotent and removes the brittle string-match
	// "duplicate" error path that the previous implementation relied on.
	res := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "group_id"}, {Name: "user_id"}},
		DoNothing: true,
	}).Create(m)
	if res.Error != nil {
		return fmt.Errorf("add member to group: %w", res.Error)
	}
	return nil
}

func (r *repository) AddMembers(ctx context.Context, groupID int64, members []*UserGroupMember) ([]int64, error) {
	if len(members) == 0 {
		return nil, nil
	}

	// Pre-fetch existing members so we can report skipped IDs deterministically;
	// ON CONFLICT DO NOTHING would tell us the total inserted but not which rows.
	userIDs := make([]int64, 0, len(members))
	for _, m := range members {
		userIDs = append(userIDs, m.UserID)
	}

	var existing []int64
	if err := r.db.WithContext(ctx).
		Model(&UserGroupMember{}).
		Where("group_id = ? AND user_id IN ?", groupID, userIDs).
		Pluck("user_id", &existing).Error; err != nil {
		return nil, fmt.Errorf("check existing members: %w", err)
	}
	existingSet := make(map[int64]struct{}, len(existing))
	for _, id := range existing {
		existingSet[id] = struct{}{}
	}

	toInsert := make([]*UserGroupMember, 0, len(members))
	skipped := make([]int64, 0)
	for _, m := range members {
		if _, ok := existingSet[m.UserID]; ok {
			skipped = append(skipped, m.UserID)
			continue
		}
		toInsert = append(toInsert, m)
	}

	if len(toInsert) == 0 {
		return skipped, nil
	}

	if err := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "group_id"}, {Name: "user_id"}},
		DoNothing: true,
	}).Create(&toInsert).Error; err != nil {
		return nil, fmt.Errorf("batch add members: %w", err)
	}
	return skipped, nil
}

func (r *repository) RemoveMember(ctx context.Context, groupID, userID int64) error {
	result := r.db.WithContext(ctx).
		Where("group_id = ? AND user_id = ?", groupID, userID).
		Delete(&UserGroupMember{})
	if result.Error != nil {
		return fmt.Errorf("remove member from group: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("member not found in group")
	}
	return nil
}

func (r *repository) RemoveMembers(ctx context.Context, groupID int64, userIDs []int64) ([]int64, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}

	var existing []int64
	if err := r.db.WithContext(ctx).
		Model(&UserGroupMember{}).
		Where("group_id = ? AND user_id IN ?", groupID, userIDs).
		Pluck("user_id", &existing).Error; err != nil {
		return nil, fmt.Errorf("check existing members: %w", err)
	}
	existingSet := make(map[int64]struct{}, len(existing))
	for _, id := range existing {
		existingSet[id] = struct{}{}
	}

	skipped := make([]int64, 0)
	toDelete := make([]int64, 0, len(userIDs))
	for _, uid := range userIDs {
		if _, ok := existingSet[uid]; !ok {
			skipped = append(skipped, uid)
			continue
		}
		toDelete = append(toDelete, uid)
	}

	if len(toDelete) == 0 {
		return skipped, nil
	}

	if err := r.db.WithContext(ctx).
		Where("group_id = ? AND user_id IN ?", groupID, toDelete).
		Delete(&UserGroupMember{}).Error; err != nil {
		return nil, fmt.Errorf("batch remove members: %w", err)
	}
	return skipped, nil
}

func (r *repository) GetMembers(ctx context.Context, groupID int64, page, pageSize int) ([]*MemberInfo, int64, error) {
	var total int64
	if err := r.db.WithContext(ctx).
		Model(&UserGroupMember{}).
		Where("group_id = ?", groupID).
		Where(liveGroupMember).
		Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count group members: %w", err)
	}

	members := make([]*MemberInfo, 0, pageSize)
	offset := (page - 1) * pageSize
	// Raw select joins mxid_user — keeps this file the only place that
	// references the user table by name, avoiding an import cycle into the
	// user domain package.
	err := r.db.WithContext(ctx).
		Table("mxid_user_group_member m").
		Select("m.user_id AS user_id, u.username AS username, u.display_name AS display_name, u.email AS email, u.avatar AS avatar, u.status AS status").
		Joins("INNER JOIN mxid_user u ON u.id = m.user_id AND u.deleted_at IS NULL").
		Where("m.group_id = ?", groupID).
		Order("m.created_at ASC").
		Offset(offset).
		Limit(pageSize).
		Scan(&members).Error
	if err != nil {
		return nil, 0, fmt.Errorf("get group members: %w", err)
	}
	return members, total, nil
}

func (r *repository) CountMembers(ctx context.Context, groupID int64) (int64, error) {
	var count int64
	if err := r.db.WithContext(ctx).
		Model(&UserGroupMember{}).
		Where("group_id = ?", groupID).
		Where(liveGroupMember).
		Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count group members: %w", err)
	}
	return count, nil
}

func (r *repository) CountMembersByGroupIDs(ctx context.Context, groupIDs []int64) (map[int64]int64, error) {
	out := make(map[int64]int64, len(groupIDs))
	if len(groupIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		GroupID int64 `gorm:"column:group_id"`
		Cnt     int64 `gorm:"column:cnt"`
	}
	if err := r.db.WithContext(ctx).
		Model(&UserGroupMember{}).
		Select("group_id, COUNT(*) AS cnt").
		Where("group_id IN ?", groupIDs).
		Where(liveGroupMember).
		Group("group_id").
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("count group members batch: %w", err)
	}
	for _, row := range rows {
		out[row.GroupID] = row.Cnt
	}
	return out, nil
}

// AllMemberIDs returns every user_id in a group. Used by the dynamic-group
// sync engine to diff against the matched set.
func (r *repository) AllMemberIDs(ctx context.Context, groupID int64) ([]int64, error) {
	ids := make([]int64, 0)
	if err := r.db.WithContext(ctx).
		Model(&UserGroupMember{}).
		Where("group_id = ?", groupID).
		Pluck("user_id", &ids).Error; err != nil {
		return nil, fmt.Errorf("list all member ids: %w", err)
	}
	return ids, nil
}

// GetRule fetches a group's dynamic rule (gorm.ErrRecordNotFound if absent).
func (r *repository) GetRule(ctx context.Context, groupID int64) (*UserGroupRule, error) {
	var rule UserGroupRule
	if err := r.db.WithContext(ctx).
		Where("group_id = ?", groupID).
		First(&rule).Error; err != nil {
		return nil, err
	}
	return &rule, nil
}

// UpsertRule replaces a group's rule. Uses ON CONFLICT on the unique
// (group_id) index so the operation is idempotent.
func (r *repository) UpsertRule(ctx context.Context, rule *UserGroupRule) error {
	res := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "group_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"expr", "status", "updated_at",
		}),
	}).Create(rule)
	if res.Error != nil {
		return fmt.Errorf("upsert rule: %w", res.Error)
	}
	return nil
}

// DeleteRule removes a group's dynamic rule. Membership rows are kept so the
// operator decides whether to prune them.
func (r *repository) DeleteRule(ctx context.Context, groupID int64) error {
	res := r.db.WithContext(ctx).
		Where("group_id = ?", groupID).
		Delete(&UserGroupRule{})
	if res.Error != nil {
		return fmt.Errorf("delete rule: %w", res.Error)
	}
	return nil
}

// MarkRuleSync records the outcome of a sync cycle. errMsg is stored when
// the sync failed so the UI can show what went wrong without re-running.
func (r *repository) MarkRuleSync(ctx context.Context, groupID int64, added, removed int, errMsg string) error {
	now := time.Now()
	updates := map[string]any{
		"last_sync_at":      now,
		"last_sync_added":   added,
		"last_sync_removed": removed,
		"updated_at":        now,
	}
	if errMsg == "" {
		updates["last_sync_error"] = nil
	} else {
		updates["last_sync_error"] = errMsg
	}
	res := r.db.WithContext(ctx).
		Model(&UserGroupRule{}).
		Where("group_id = ?", groupID).
		Updates(updates)
	if res.Error != nil {
		return fmt.Errorf("mark sync: %w", res.Error)
	}
	return nil
}

// EvaluateRule runs the compiled WHERE clause against mxid_user and returns
// the matching user IDs. The WHERE fragment was assembled exclusively from
// the rule field allow-list (see rule.go), so the raw SQL is safe.
func (r *repository) EvaluateRule(ctx context.Context, tenantID int64, cr *CompiledRule) ([]int64, error) {
	sql := buildEvaluateSQL(cr)
	args := append([]any{tenantID}, cr.Args...)

	ids := make([]int64, 0)
	if err := r.db.WithContext(ctx).
		Raw(sql, args...).
		Scan(&ids).Error; err != nil {
		return nil, fmt.Errorf("evaluate rule: %w", err)
	}
	return ids, nil
}
