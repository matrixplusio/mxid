package cas

// CASConfig holds CAS-specific settings from app.protocol_config JSONB.
type CASConfig struct {
	ServiceURLs      []string          `json:"service_urls"`      // allowed service URLs
	AttributeMapping map[string]string `json:"attribute_mapping"` // user attr -> CAS attribute name
	RoleAttribute    string            `json:"role_attribute"`    // multi-value attribute name carrying the user's app roles (JIT-first). Default "roles"; set "memberOf"/"groups" to match the SP.
	TicketTTL        int               `json:"ticket_ttl"`        // seconds, default 30
	RenewEnabled     bool              `json:"renew_enabled"`     // force re-authentication
	LogoutURL        string            `json:"logout_url"`        // SP's CAS Single Logout endpoint; falls back to the service URL if empty

	// ProxyEnabled opts this app into CAS proxy authentication (PGT/PT, the
	// /proxy + /proxyValidate endpoints). Off by default — proxy chains are a
	// niche feature and each hop widens the attack surface, so it is fail-closed:
	// with it off, a pgtUrl on serviceValidate is ignored and /proxy is refused.
	ProxyEnabled bool `json:"proxy_enabled"`
	// PGTicketTTL is the proxy-granting-ticket lifetime in seconds. A PGT is
	// reusable (mints many proxy tickets) so it lives far longer than a
	// single-use service ticket, but still bounded. Default 7200 (2h).
	PGTicketTTL int `json:"pgt_ticket_ttl"`
}

// Defaults returns a CASConfig with sane defaults.
func Defaults() *CASConfig {
	return &CASConfig{
		TicketTTL:     30,
		PGTicketTTL:   7200,
		RenewEnabled:  false,
		RoleAttribute: "roles",
		AttributeMapping: map[string]string{
			"username":     "uid",
			"email":        "mail",
			"display_name": "displayName",
			"phone":        "telephoneNumber",
		},
	}
}
