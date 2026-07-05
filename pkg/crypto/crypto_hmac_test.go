// pkg/crypto/crypto_hmac_test.go
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHMACSHA256_MatchesStdlib(t *testing.T) {
	key := []byte("test-key")
	data := []byte("hello world")

	got := HMACSHA256(key, data)

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	want := mac.Sum(nil)

	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("HMACSHA256 = %x, want %x", got, want)
	}
	if len(got) != 32 {
		t.Fatalf("len = %d, want 32", len(got))
	}
}
