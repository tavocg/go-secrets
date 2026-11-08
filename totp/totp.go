// Package totp provides TOTP enrollment and verification with atomic consumption.
package totp

import (
	"bytes"
	"image/png"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// ConsumeFunc returns true only after atomically checking that secret is still
// active for identity and counter exceeds its last accepted counter, then
// recording counter. Return false on replay, secret changes, or storage failure.
// Persist this state with the credential and share it across all verifiers.
type ConsumeFunc func(identity, secret string, counter uint64) bool

// Manager wires TOTP enrollment and verification to caller-provided secret
// loading, storage, and atomic consumption callbacks.
type Manager struct {
	secret  func(identity string) string
	store   func(identity, secret string) error
	consume ConsumeFunc
	issuer  string
}

// NewManager creates a TOTP manager for the issuer.
func NewManager(
	issuer string,
	secret func(identity string) string,
	store func(identity, secret string) error,
	consume ConsumeFunc,
) (*Manager, error) {
	if secret == nil {
		return nil, errStr("nil secret callback")
	}

	if store == nil {
		return nil, errStr("nil store callback")
	}
	if consume == nil {
		return nil, errStr("nil consume callback")
	}

	return &Manager{
		secret:  secret,
		store:   store,
		consume: consume,
		issuer:  issuer,
	}, nil
}

// Enrollment creates enrollment data for an account.
func (m *Manager) Enrollment(account string, imageSize ...int) (url string, qrpng []byte, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuer,
		AccountName: account,
		// Default pquerna/otp/totp.GenerateOpts options.
		Period:     30,
		SecretSize: 20,
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", nil, err
	}

	var buf bytes.Buffer
	if len(imageSize) > 0 {
		size := imageSize[0]
		img, err := key.Image(size, size)
		if err != nil {
			return "", nil, err
		}
		if err := png.Encode(&buf, img); err != nil {
			return "", nil, err
		}
	}
	if err := m.store(account, key.Secret()); err != nil {
		return "", nil, err
	}
	return key.URL(), buf.Bytes(), nil
}

// Verify checks and consumes a passcode for an identity. It uses 30-second
// intervals with one interval of clock skew in either direction.
func (m *Manager) Verify(identity, passcode string) bool {
	return m.verifyAt(identity, passcode, time.Now())
}

func (m *Manager) verifyAt(identity, passcode string, now time.Time) bool {
	if identity == "" || now.Unix() < 0 {
		return false
	}
	secret := m.secret(identity)
	if secret == "" {
		return false
	}

	current := now.Unix() / 30
	// Consume the newest matching counter once; never try another interval
	// after storage rejects a match.
	for counter := current + 1; counter >= 0 && counter >= current-1; counter-- {
		valid, err := hotp.ValidateCustom(passcode, uint64(counter), secret, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return false
		}
		if valid {
			return m.consume(identity, secret, uint64(counter))
		}
	}
	return false
}
