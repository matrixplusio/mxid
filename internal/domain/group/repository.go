package group

import "context"

// Repository defines the data access interface for user groups.
type Repository interface {
	Create(ctx context.Context, g *UserGroup) error
	GetByID(ctx context.Context, id int64) (*UserGroup, error)
	Update(ctx context.Context, g *UserGroup) error
	Delete(ctx context.Context, id int64) error
	// List filters by tenant_id; keyword (optional) matches name/code/description (ILIKE).
	List(ctx context.Context, tenantID int64, keyword string, page, pageSize int) ([]*UserGroup, int64, error)
	// ListByUserID returns all groups a user belongs to (no pagination — a user
	// rarely belongs to enough groups for this to matter, and the console renders
	// them inline on the user detail page).
	ListByUserID(ctx context.Context, tenantID, userID int64) ([]*UserGroup, error)
	// ListDynamicGroupIDs returns the IDs of every dynamic (rule-driven) group
	// in the tenant. Used to fan out a re-sync when org membership changes.
	ListDynamicGroupIDs(ctx context.Context, tenantID int64) ([]int64, error)

	// Members
	AddMember(ctx context.Context, m *UserGroupMember) error
	// AddMembers inserts multiple members in a single transaction. UserIDs that
	// already belong to the group are reported in skipped, not as errors.
	AddMembers(ctx context.Context, groupID int64, members []*UserGroupMember) (skipped []int64, err error)
	RemoveMember(ctx context.Context, groupID, userID int64) error
	// RemoveMembers deletes multiple members in a single statement. UserIDs not
	// currently in the group are reported in skipped.
	RemoveMembers(ctx context.Context, groupID int64, userIDs []int64) (skipped []int64, err error)
	// GetMembers returns enriched member rows joined against mxid_user.
	GetMembers(ctx context.Context, groupID int64, page, pageSize int) ([]*MemberInfo, int64, error)
	CountMembers(ctx context.Context, groupID int64) (int64, error)
	// CountMembersByGroupIDs returns member counts for many groups in ONE grouped
	// query, avoiding the N+1 of calling CountMembers per group in a list loop.
	// Groups with zero members are absent from the map (caller treats missing as 0).
	CountMembersByGroupIDs(ctx context.Context, groupIDs []int64) (map[int64]int64, error)
	// AllMemberIDs returns every user_id in the group, unpaged. Used by the
	// dynamic-group sync engine to compute the diff against the rule's
	// matched set; group memberships rarely exceed a few thousand rows.
	AllMemberIDs(ctx context.Context, groupID int64) ([]int64, error)

	// Dynamic rule persistence.
	GetRule(ctx context.Context, groupID int64) (*UserGroupRule, error)
	UpsertRule(ctx context.Context, rule *UserGroupRule) error
	DeleteRule(ctx context.Context, groupID int64) error
	MarkRuleSync(ctx context.Context, groupID int64, added, removed int, errMsg string) error
	// EvaluateRule runs a CompiledRule and returns the user IDs that match,
	// scoped to the given tenant.
	EvaluateRule(ctx context.Context, tenantID int64, cr *CompiledRule) ([]int64, error)
}
