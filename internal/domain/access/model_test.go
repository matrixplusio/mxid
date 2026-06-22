package access

import "testing"

func TestEligibility_DurationAllowed(t *testing.T) {
	e := &Eligibility{AllowedDurations: []int{3600, 14400}, MaxDurationSeconds: 14400}
	if !e.DurationAllowed(3600) {
		t.Fatal("3600 should be allowed")
	}
	if e.DurationAllowed(7200) {
		t.Fatal("7200 not in allowed set")
	}
}

func TestEligibility_ClampDuration(t *testing.T) {
	e := &Eligibility{AllowedDurations: []int{3600, 999999}, MaxDurationSeconds: 14400}
	if got := e.ClampDuration(999999); got != 14400 {
		t.Fatalf("want clamp to 14400, got %d", got)
	}
}
