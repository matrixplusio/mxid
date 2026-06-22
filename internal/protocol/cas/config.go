package cas

// CASConfig holds CAS-specific settings from app.protocol_config JSONB.
type CASConfig struct {
	ServiceURLs      []string          `json:"service_urls"`      // allowed service URLs
	AttributeMapping map[string]string `json:"attribute_mapping"` // user attr -> CAS attribute name
	TicketTTL        int               `json:"ticket_ttl"`        // seconds, default 30
	RenewEnabled     bool              `json:"renew_enabled"`     // force re-authentication
	LogoutURL        string            `json:"logout_url"`        // SP's CAS Single Logout endpoint; falls back to the service URL if empty
}

// Defaults returns a CASConfig with sane defaults.
func Defaults() *CASConfig {
	return &CASConfig{
		TicketTTL:    30,
		RenewEnabled: false,
		AttributeMapping: map[string]string{
			"username":     "uid",
			"email":        "mail",
			"display_name": "displayName",
			"phone":        "telephoneNumber",
		},
	}
}
