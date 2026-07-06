// internal/domain/audit/merkle_test.go
package audit

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func h2(a, b []byte) []byte {
	s := sha256.Sum256(append(append([]byte{}, a...), b...))
	return s[:]
}

func TestMerkleRoot_Empty(t *testing.T) {
	if MerkleRoot(nil) != nil {
		t.Fatal("empty should be nil")
	}
}

func TestMerkleRoot_Single(t *testing.T) {
	leaf := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !bytes.Equal(MerkleRoot([][]byte{leaf}), leaf) {
		t.Fatal("single leaf is its own root")
	}
}

func TestMerkleRoot_Two(t *testing.T) {
	a := []byte("a")
	b := []byte("b")
	got := MerkleRoot([][]byte{a, b})
	if !bytes.Equal(got, h2(a, b)) {
		t.Fatalf("two-leaf root mismatch")
	}
}

func TestMerkleRoot_Three_DuplicatesLast(t *testing.T) {
	a, b, c := []byte("a"), []byte("b"), []byte("c")
	// level1: h(a,b), h(c,c); root: h(h(a,b), h(c,c))
	want := h2(h2(a, b), h2(c, c))
	got := MerkleRoot([][]byte{a, b, c})
	if !bytes.Equal(got, want) {
		t.Fatalf("three-leaf duplicate-last root mismatch")
	}
}

func TestMerkleRoot_Deterministic(t *testing.T) {
	ls := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	if !bytes.Equal(MerkleRoot(ls), MerkleRoot(ls)) {
		t.Fatal("not deterministic")
	}
}
