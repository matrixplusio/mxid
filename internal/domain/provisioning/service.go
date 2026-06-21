package provisioning

import (
	"context"
	"errors"
	"fmt"

	"github.com/imkerbos/mxid/pkg/crypto"
)

// Service wraps the repo with token encryption + the read hooks offboarding and
// the EE SCIM connector use.
type Service struct {
	repo      Repository
	masterKey *crypto.MasterKey
}

// NewService builds the provisioning service.
func NewService(repo Repository, masterKey *crypto.MasterKey) *Service {
	return &Service{repo: repo, masterKey: masterKey}
}

// View is the API-safe projection (no token).
type View struct {
	AppID     int64  `json:"app_id,string"`
	Enabled   bool   `json:"enabled"`
	Connector string `json:"connector"`
	BaseURL   string `json:"base_url"`
	TokenSet  bool   `json:"token_set"`
}

// Get returns the API-safe view for an app (zero-value when unset).
func (s *Service) Get(ctx context.Context, appID int64) (View, error) {
	c, err := s.repo.GetByApp(ctx, appID)
	if errors.Is(err, ErrNotFound) {
		return View{AppID: appID, Connector: ConnectorSCIM2}, nil
	}
	if err != nil {
		return View{}, err
	}
	return View{
		AppID:     c.AppID,
		Enabled:   c.Enabled,
		Connector: c.Connector,
		BaseURL:   c.BaseURL,
		TokenSet:  c.TokenEnc != "",
	}, nil
}

// SaveInput updates an app's provisioning config. A blank Token keeps the
// existing one (the API never echoes it back, so an unchanged save omits it).
type SaveInput struct {
	AppID     int64
	TenantID  int64
	Enabled   bool
	Connector string
	BaseURL   string
	Token     string // plaintext; "" = keep existing
}

// Save upserts the config, encrypting the token at rest.
func (s *Service) Save(ctx context.Context, in SaveInput) error {
	if in.Connector == "" {
		in.Connector = ConnectorSCIM2
	}
	c, err := s.repo.GetByApp(ctx, in.AppID)
	if errors.Is(err, ErrNotFound) {
		c = &Config{AppID: in.AppID}
	} else if err != nil {
		return err
	}
	c.TenantID = in.TenantID
	c.Enabled = in.Enabled
	c.Connector = in.Connector
	c.BaseURL = in.BaseURL
	if in.Token != "" {
		enc, err := s.masterKey.Encrypt([]byte(in.Token))
		if err != nil {
			return fmt.Errorf("encrypt provisioning token: %w", err)
		}
		c.TokenEnc = enc
	}
	return s.repo.Upsert(ctx, c)
}

// Enabled reports whether an app has provisioning turned on. Used by
// offboarding to classify an app as L2 (downstream deprovision).
func (s *Service) Enabled(ctx context.Context, appID int64) bool {
	c, err := s.repo.GetByApp(ctx, appID)
	return err == nil && c.Enabled && c.BaseURL != ""
}

// Resolved returns the live, decrypted config for delivery — the hook the EE
// SCIM connector calls at deprovision time. Returns enabled=false when unset or
// off so the connector no-ops.
func (s *Service) Resolved(ctx context.Context, appID int64) (enabled bool, connector, baseURL, token string, err error) {
	c, gerr := s.repo.GetByApp(ctx, appID)
	if errors.Is(gerr, ErrNotFound) {
		return false, "", "", "", nil
	}
	if gerr != nil {
		return false, "", "", "", gerr
	}
	if !c.Enabled {
		return false, c.Connector, c.BaseURL, "", nil
	}
	if c.TokenEnc != "" {
		plain, derr := s.masterKey.Decrypt(c.TokenEnc)
		if derr != nil {
			return false, "", "", "", fmt.Errorf("decrypt provisioning token: %w", derr)
		}
		token = string(plain)
	}
	return true, c.Connector, c.BaseURL, token, nil
}
