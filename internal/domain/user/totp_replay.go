package user

import (
	"context"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
)

// TOTP single-use (replay) protection.
//
// pquerna/otp's totp.Validate accepts a code anywhere in a ±1 step window
// (~90s) and is stateless: the SAME code validates repeatedly until it
// rolls out of the window. OWASP A07 calls this a replay weakness — an
// attacker who observes one in-flight code (shoulder-surf, MITM on a
// non-pinned channel, log leak) can reuse it within the window.
//
// Fix: remember the highest RFC6238 time-step we have already consumed per
// (user, factor) and reject any code whose matched step is <= that stored
// value. The store is Redis with a short TTL (window + one skew step) — the
// existing MFA rate limiter already proves the Redis-counter pattern on this
// hot path, and TTL auto-expiry frees us from any cleanup job. A code is
// thus usable exactly once; a later, higher step is still accepted (normal
// 30s rotation) while the same or an earlier step is treated as a replay.

const (
	totpPeriodSeconds = 30
	totpSkewSteps     = 1
	// totpUsedKeyPrefix namespaces the per-user last-consumed-step key.
	totpUsedKeyPrefix = "mxid:totp_used:"
	// totpUsedTTL covers the validation window (current step ± skew) plus a
	// little slack so a still-valid earlier code can't be replayed after the
	// key expires. window = (2*skew+1) steps; +1 step of slack.
	totpUsedTTL = time.Duration(totpPeriodSeconds*(2*totpSkewSteps+2)) * time.Second
)

// totpClaimScript atomically stores the matched step only when it is strictly
// greater than the currently-stored one, returning 1 on success (claimed) or
// 0 when the step was already consumed (replay). Doing the compare-and-set in
// one round-trip closes the race where two concurrent requests carrying the
// same code could both pass a read-then-write check.
//
// KEYS[1]=used-step key. ARGV[1]=matched step, ARGV[2]=TTL ms.
var totpClaimScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
local step = tonumber(ARGV[1])
if cur and tonumber(cur) >= step then
  return 0
end
redis.call('SET', KEYS[1], step, 'PX', ARGV[2])
return 1
`)

// SetTOTPReplayGuard wires the Redis client used for single-use enforcement.
// Called by main.go after the app's redis client exists. When unset (tests
// without redis) VerifyTOTP keeps its prior behaviour minus replay
// protection — production must always wire this.
func (s *Service) SetTOTPReplayGuard(rdb *redis.Client) { s.totpReplayRDB = rdb }

func totpUsedKey(userID int64) string {
	return totpUsedKeyPrefix + strconv.FormatInt(userID, 10)
}

// matchTOTPStep returns the RFC6238 time-step whose code equals the supplied
// one, scanning the same ±skew window pquerna/otp's default validator uses.
// The second return is false when no step in the window matches (wrong code).
//
// totp.Validate hides the matched step, so we re-implement the window walk
// with totp.ValidateCustom(skew=0) per candidate step: the step that returns
// valid is the one to claim. The opts MUST mirror enrollment (SHA1/30s/6
// digits) — see SetupTOTP.
func (s *Service) matchTOTPStep(code, secret string) (int64, bool) {
	now := time.Now()
	opts := totp.ValidateOpts{
		Period:    totpPeriodSeconds,
		Skew:      0, // exact step — we widen the window ourselves below
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	// Check the current step first (dominant case), then the skew neighbours.
	// Order doesn't affect correctness: at most one step matches a given code.
	for _, delta := range stepDeltas() {
		t := now.Add(time.Duration(delta) * totpPeriodSeconds * time.Second)
		valid, err := totp.ValidateCustom(code, secret, t, opts)
		if err == nil && valid {
			return int64(t.Unix()) / totpPeriodSeconds, true
		}
	}
	return 0, false
}

// stepDeltas lists the step offsets to probe: 0, then ±1..±skew. Centring on
// 0 keeps the common (in-sync clock) case first.
func stepDeltas() []int {
	deltas := []int{0}
	for i := 1; i <= totpSkewSteps; i++ {
		deltas = append(deltas, i, -i)
	}
	return deltas
}

// claimTOTPStep atomically claims matchedStep for userID. Returns:
//   - (true, nil)  fresh step, claimed.
//   - (false, nil) genuine replay — the step was already consumed.
//   - (false, err) store failure — the caller must fail CLOSED, but this is NOT
//     a replay, so it surfaces a generic invalid-code rather than the
//     "code already used" hint (which would mislead while Redis is down).
//
// When no redis is wired it returns (true, nil) so the (test-only) path stays
// functional.
func (s *Service) claimTOTPStep(ctx context.Context, userID int64, matchedStep int64) (bool, error) {
	if s.totpReplayRDB == nil {
		return true, nil
	}
	res, err := totpClaimScript.Run(ctx, s.totpReplayRDB,
		[]string{totpUsedKey(userID)},
		matchedStep, totpUsedTTL.Milliseconds(),
	).Int64()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}
