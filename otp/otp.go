// Package otp derives keyed digests for one-time verification codes.
package otp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
)

// Signer stores only an HMAC-SHA-256 digest of a code. The purpose and
// identity are part of the signed message so a digest cannot be replayed
// across flows or accounts.
type Signer struct {
	key []byte
}

// NewSigner creates a signer with an application-specific HMAC key. The key
// should be independent from other signing keys and contain at least 32 random
// bytes.
func NewSigner(secret string) (*Signer, error) {
	if secret == "" {
		return nil, errors.New("otp HMAC secret is required")
	}

	return &Signer{key: []byte(secret)}, nil
}

// Sign returns the hexadecimal HMAC-SHA-256 digest for purpose, identity and
// code. Fields are length-prefixed to avoid ambiguous concatenations.
func (s *Signer) Sign(purpose, identity, code string) string {
	mac := hmac.New(sha256.New, s.key)
	writeField(mac, purpose)
	writeField(mac, identity)
	writeField(mac, code)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether digest is the expected HMAC for the supplied context.
// The comparison is constant time.
func (s *Signer) Verify(purpose, identity, code, digest string) bool {
	return hmac.Equal([]byte(s.Sign(purpose, identity, code)), []byte(digest))
}

func writeField(mac hash.Hash, field string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(field)))
	_, _ = mac.Write(size[:])
	_, _ = mac.Write([]byte(field))
}
