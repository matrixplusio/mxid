// internal/domain/audit/anchor.go
package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/imkerbos/mxid/pkg/crypto"
)

const anchorSigDomain = "mxid-audit-anchor-v1"

// AnchorSigMessage builds the FROZEN signed message binding a Merkle root to its
// chain and seq range: domain ‖ tenant(be8) ‖ len(class)(be2) ‖ class ‖
// from(be8) ‖ to(be8) ‖ root.
func AnchorSigMessage(tenantID int64, class string, fromSeq, toSeq int64, root []byte) []byte {
	buf := make([]byte, 0, len(anchorSigDomain)+8+2+len(class)+8+8+len(root))
	buf = append(buf, anchorSigDomain...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], uint64(tenantID))
	buf = append(buf, b8[:]...)
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], uint16(len(class)))
	buf = append(buf, b2[:]...)
	buf = append(buf, class...)
	binary.BigEndian.PutUint64(b8[:], uint64(fromSeq))
	buf = append(buf, b8[:]...)
	binary.BigEndian.PutUint64(b8[:], uint64(toSeq))
	buf = append(buf, b8[:]...)
	buf = append(buf, root...)
	return buf
}

// KeyIDForPublic is the first 16 hex chars of SHA256(pub) — a short stable id.
func KeyIDForPublic(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// SignAnchor signs the canonical anchor message.
func SignAnchor(priv ed25519.PrivateKey, tenantID int64, class string, fromSeq, toSeq int64, root []byte) []byte {
	return crypto.Ed25519Sign(priv, AnchorSigMessage(tenantID, class, fromSeq, toSeq, root))
}

// VerifyAnchorSig recomputes the canonical message from the anchor's fields and
// verifies its signature.
func VerifyAnchorSig(pub ed25519.PublicKey, a *AuditAnchor) bool {
	msg := AnchorSigMessage(a.TenantID, a.ChainClass, a.FromSeq, a.ToSeq, a.MerkleRoot)
	return crypto.Ed25519Verify(pub, msg, a.Signature)
}
