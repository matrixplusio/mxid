package conditionalaccess

import (
	"context"
	"time"

	"github.com/imkerbos/mxid/pkg/geoip"
)

// LoginEvent is one past successful login, used to derive geo/velocity signals.
type LoginEvent struct {
	IP string
	At time.Time
}

// LoginHistory yields a user's recent successful logins, newest first.
type LoginHistory interface {
	RecentSuccessful(ctx context.Context, userID int64, limit int) ([]LoginEvent, error)
}

// deviceChecker is the slice of DeviceService the computer needs (lets tests
// inject a fake without a repo).
type deviceChecker interface {
	IsKnown(ctx context.Context, userID int64, deviceID string) (bool, error)
}

// SignalComputer turns a login attempt + history into risk Signals. Pure
// Evaluate consumes the result; this is the impure, adapter-backed half.
type SignalComputer struct {
	geo     geoip.Resolver
	history LoginHistory
	devices deviceChecker
	now     func() time.Time
	// historyLimit bounds how many past logins we scan for the new-country set.
	historyLimit int
}

// NewSignalComputer wires a computer. historyLimit defaults to 50.
func NewSignalComputer(geo geoip.Resolver, history LoginHistory, devices deviceChecker) *SignalComputer {
	return &SignalComputer{geo: geo, history: history, devices: devices, now: time.Now, historyLimit: 50}
}

// ComputeInput is one login attempt's context.
type ComputeInput struct {
	UserID                 int64
	IP                     string
	DeviceID               string
	ImpossibleTravelWindow time.Duration // a country change within this window is "impossible travel"
}

// Compute derives the risk Signals. It is conservative: when geo is unknown
// (no db / private IP) it does NOT raise geo signals, to avoid false positives.
func (c *SignalComputer) Compute(ctx context.Context, in ComputeInput) (Signals, error) {
	var s Signals

	known, err := c.devices.IsKnown(ctx, in.UserID, in.DeviceID)
	if err != nil {
		return s, err
	}
	s.NewDevice = !known

	curCountry := c.country(in.IP)

	hist, err := c.history.RecentSuccessful(ctx, in.UserID, c.historyLimit)
	if err != nil {
		return s, err
	}

	// The CURRENT login is already persisted to the history store before
	// conditional-access runs (the login-success event records it synchronously),
	// so it comes back as the newest row. Left in, it makes NewCountry and
	// ImpossibleTravel compare the login against ITSELF (same IP, same country,
	// ~0s apart) and NEVER fire. Drop the just-written current-login row(s) —
	// same IP within a few seconds — so we compare only against genuinely PRIOR
	// logins. Same-IP rows can't trip either geo signal anyway (identical
	// country), so excluding them is safe.
	prior := make([]LoginEvent, 0, len(hist))
	for _, h := range hist {
		if h.IP == in.IP && c.now().Sub(h.At) < 5*time.Second {
			continue
		}
		prior = append(prior, h)
	}
	hist = prior

	// New country: current country resolved, non-empty, and not present in the
	// set of countries seen in recent successful logins. Empty history (first
	// login) is never "new country" — there is nothing to compare against.
	if curCountry != "" && len(hist) > 0 {
		seen := false
		for _, h := range hist {
			if c.country(h.IP) == curCountry {
				seen = true
				break
			}
		}
		s.NewCountry = !seen
	}

	// Impossible travel: the most recent prior login was from a different
	// country less than the configured window ago. Proxy for real velocity
	// (no lat/lon available); a sub-hour intercontinental jump is the signal.
	if curCountry != "" && len(hist) > 0 && in.ImpossibleTravelWindow > 0 {
		last := hist[0]
		lastCountry := c.country(last.IP)
		if lastCountry != "" && lastCountry != curCountry &&
			c.now().Sub(last.At) < in.ImpossibleTravelWindow {
			s.ImpossibleTravel = true
		}
	}

	return s, nil
}

func (c *SignalComputer) country(ip string) string {
	loc, err := c.geo.Lookup(ip)
	if err != nil {
		return ""
	}
	return loc.Country
}
