package totp

import "time"

// ConsumeFunc returns true only after atomically checking that secret is still
// active for identity and counter exceeds its last accepted counter, then
// recording counter. Return false on replay, secret changes, or storage failure.
type ConsumeFunc func(identity, secret string, counter uint64) bool

// ActivateFunc atomically checks that the pending secret matches, is unexpired,
// and was created for the current credential generation. It then replaces the
// active secret, records counter as consumed, and removes the pending enrollment.
// Return false without changing the credential if any check or storage fails.
type ActivateFunc func(identity, secret string, counter uint64) bool

// Storage supplies durable, shared credential and enrollment storage. Callbacks
// must be safe for concurrent use; reads return an empty secret on storage errors.
type Storage struct {
	// Secret loads the active credential, never the pending enrollment.
	Secret func(identity string) string
	// Consume persists the highest accepted counter with the active credential.
	Consume ConsumeFunc
	// Pending loads the identity-bound pending secret and its expiration.
	Pending func(identity string) (secret string, expiresAt time.Time)
	// StorePending replaces only the pending enrollment, binding it to the
	// current credential generation. It must leave the active credential intact.
	StorePending func(identity, secret string, expiresAt time.Time) error
	// Activate performs the entire credential replacement in one atomic write.
	Activate ActivateFunc
}
