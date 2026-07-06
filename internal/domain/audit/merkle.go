package audit

import "crypto/sha256"

// MerkleRoot returns the SHA-256 Merkle root over leaves, in the given order.
// FROZEN scheme (verification depends on it): internal node = SHA256(left‖right);
// an odd node count duplicates the last node at that level; a single leaf is its
// own root; nil for an empty input.
func MerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1]) // duplicate last
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.New()
			h.Write(level[i])
			h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
	}
	return level[0]
}
