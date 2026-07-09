package dashboard

import "time"

// Overview is the single aggregated payload the console dashboard renders.
// One round-trip drives every card / chart / panel so the page paints in a
// single request instead of fanning out to a dozen count endpoints.
type Overview struct {
	Counts      Counts        `json:"counts"`
	Auth        AuthHealth    `json:"auth"`
	LoginTrend  []TrendPoint  `json:"login_trend"`
	AuthMethods []NameValue   `json:"auth_methods"`
	TopApps     []NameValue   `json:"top_apps"`
	GeoTop      []NameValue   `json:"geo_top"`
	Security    SecurityPanel `json:"security"`
	RangeDays   int           `json:"range_days"`
	GeneratedAt time.Time     `json:"generated_at"`
}

// Counts are point-in-time inventory metrics (not range-bound).
type Counts struct {
	Users           int64       `json:"users"`
	UsersActive     int64       `json:"users_active"`
	Apps            int64       `json:"apps"`
	AppsByProtocol  []NameValue `json:"apps_by_protocol"`
	Orgs            int64       `json:"orgs"`
	Groups          int64       `json:"groups"`
	IdentitySources int64       `json:"identity_sources"`
	ActiveSessions  int64       `json:"active_sessions"`
	MFAEnrolled     int64       `json:"mfa_enrolled"`
	MFACoverage     float64     `json:"mfa_coverage"` // 0..1, mfa_enrolled / active users
	NewUsers        int64       `json:"new_users"`    // created within range
}

// AuthHealth covers authentication volume + quality over the selected range,
// plus the standard DAU / WAU / MAU active-user windows.
type AuthHealth struct {
	TodayLogins  int64   `json:"today_logins"`
	LoginSuccess int64   `json:"login_success"` // over range
	LoginFailed  int64   `json:"login_failed"`  // over range
	SuccessRate  float64 `json:"success_rate"`  // 0..1
	DAU          int64   `json:"dau"`
	WAU          int64   `json:"wau"`
	MAU          int64   `json:"mau"`
}

// TrendPoint is one day in the login trend line. Days with no activity are
// emitted as zero so the chart line stays continuous.
type TrendPoint struct {
	Date    string `json:"date"` // YYYY-MM-DD
	Success int64  `json:"success"`
	Failed  int64  `json:"failed"`
}

// NameValue is a generic label/count pair for donut + bar charts.
type NameValue struct {
	Name  string `json:"name" gorm:"column:name"`
	Value int64  `json:"value" gorm:"column:value"`
}

// SecurityPanel summarizes security-relevant events over the range plus a
// recent feed for the activity list.
type SecurityPanel struct {
	RiskEvents       int64           `json:"risk_events"`
	LockedUsers      int64           `json:"locked_users"`
	TokenReuse       int64           `json:"token_reuse"`
	SuperAdminGrants int64           `json:"super_admin_grants"`
	PIIViews         int64           `json:"pii_views"`
	Recent           []SecurityEvent `json:"recent"`
}

// SecurityEvent is one row in the security feed.
type SecurityEvent struct {
	Time      time.Time `json:"time"`
	EventType string    `json:"event_type"`
	Actor     string    `json:"actor"`
	IP        string    `json:"ip"`
}
