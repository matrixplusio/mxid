package conditionalaccess

import (
	"context"
	"testing"
	"time"

	"github.com/imkerbos/mxid/pkg/geoip"
)

type fakeGeo map[string]string // ip -> ISO country

func (f fakeGeo) Lookup(ip string) (geoip.Location, error) {
	return geoip.Location{Country: f[ip]}, nil
}

type fakeHistory []LoginEvent

func (f fakeHistory) RecentSuccessful(context.Context, int64, int) ([]LoginEvent, error) {
	return []LoginEvent(f), nil
}

type fakeDev struct{ known bool }

func (f fakeDev) IsKnown(context.Context, int64, string) (bool, error) { return f.known, nil }

func newComputer(geo fakeGeo, hist fakeHistory, knownDevice bool, now time.Time) *SignalComputer {
	c := NewSignalComputer(geo, hist, fakeDev{known: knownDevice})
	c.now = func() time.Time { return now }
	return c
}

func TestCompute_NewDevice(t *testing.T) {
	c := newComputer(fakeGeo{}, fakeHistory{}, false, time.Unix(1000, 0))
	s, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "8.8.8.8", DeviceID: "d1"})
	if !s.NewDevice {
		t.Fatalf("unknown device must be NewDevice")
	}

	c2 := newComputer(fakeGeo{}, fakeHistory{}, true, time.Unix(1000, 0))
	s2, _ := c2.Compute(context.Background(), ComputeInput{UserID: 1, IP: "8.8.8.8", DeviceID: "d1"})
	if s2.NewDevice {
		t.Fatalf("known device must not be NewDevice")
	}
}

func TestCompute_NewCountry(t *testing.T) {
	geo := fakeGeo{"1.1.1.1": "US", "2.2.2.2": "CN"}
	now := time.Unix(100000, 0)

	// History only from US; current login from CN → new country.
	hist := fakeHistory{{IP: "1.1.1.1", At: now.Add(-48 * time.Hour)}}
	c := newComputer(geo, hist, true, now)
	s, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "2.2.2.2", DeviceID: "d"})
	if !s.NewCountry {
		t.Fatalf("CN login with only US history must be NewCountry")
	}

	// Current country already in history → not new.
	s2, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "1.1.1.1", DeviceID: "d"})
	if s2.NewCountry {
		t.Fatalf("US login with US history must not be NewCountry")
	}
}

func TestCompute_FirstLoginNoGeoSignals(t *testing.T) {
	c := newComputer(fakeGeo{"2.2.2.2": "CN"}, fakeHistory{}, false, time.Unix(1, 0))
	s, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "2.2.2.2", DeviceID: "d"})
	if s.NewCountry || s.ImpossibleTravel {
		t.Fatalf("empty history must not raise geo signals, got %+v", s)
	}
}

func TestCompute_ImpossibleTravel(t *testing.T) {
	geo := fakeGeo{"1.1.1.1": "US", "2.2.2.2": "CN"}
	now := time.Unix(100000, 0)
	window := time.Hour

	// Last login US 30 min ago, now CN → impossible travel.
	hist := fakeHistory{{IP: "1.1.1.1", At: now.Add(-30 * time.Minute)}}
	c := newComputer(geo, hist, true, now)
	s, _ := c.Compute(context.Background(), ComputeInput{UserID: 1, IP: "2.2.2.2", DeviceID: "d", ImpossibleTravelWindow: window})
	if !s.ImpossibleTravel {
		t.Fatalf("US→CN in 30min must be impossible travel")
	}

	// Same hop but 2h ago → outside window, not impossible.
	hist2 := fakeHistory{{IP: "1.1.1.1", At: now.Add(-2 * time.Hour)}}
	c2 := newComputer(geo, hist2, true, now)
	s2, _ := c2.Compute(context.Background(), ComputeInput{UserID: 1, IP: "2.2.2.2", DeviceID: "d", ImpossibleTravelWindow: window})
	if s2.ImpossibleTravel {
		t.Fatalf("US→CN in 2h must NOT be impossible travel")
	}
}

func TestCompute_ExcludesCurrentLoginFromHistory(t *testing.T) {
	// Reproduces the production path the earlier tests missed: the CURRENT login
	// is persisted to the history store (newest row, same IP as the request,
	// ~now) BEFORE Compute runs. It must be excluded, else the login is compared
	// against itself and NewCountry / ImpossibleTravel can never fire.
	geo := fakeGeo{"1.1.1.1": "US", "2.2.2.2": "CN"}
	now := time.Unix(100000, 0)
	hist := fakeHistory{
		{IP: "2.2.2.2", At: now},                         // the just-written CURRENT login (CN)
		{IP: "1.1.1.1", At: now.Add(-30 * time.Minute)},  // the real prior login (US)
	}
	c := newComputer(geo, hist, true, now)
	s, _ := c.Compute(context.Background(), ComputeInput{
		UserID: 1, IP: "2.2.2.2", DeviceID: "d", ImpossibleTravelWindow: time.Hour,
	})
	if !s.NewCountry {
		t.Fatal("CN login must be NewCountry even though the current CN login is in history")
	}
	if !s.ImpossibleTravel {
		t.Fatal("US(30m ago)→CN must be impossible travel even though the current login is in history")
	}
}

func TestCompute_UnknownGeoNoSignals(t *testing.T) {
	// Geo unknown (empty) so no geo signals fire, even with history present.
	c := newComputer(fakeGeo{}, fakeHistory{{IP: "9.9.9.9", At: time.Unix(1, 0)}}, true, time.Unix(100, 0))
	s, _ := c.Compute(context.Background(), ComputeInput{
		UserID: 1, IP: "203.0.113.7", DeviceID: "d",
		ImpossibleTravelWindow: time.Hour,
	})
	if s.NewCountry || s.ImpossibleTravel {
		t.Fatalf("unknown geo must not raise geo signals")
	}
}
