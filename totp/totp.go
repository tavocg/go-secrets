// Package totp is just a wrapper for github.com/pquerna/otp.
package totp

import (
	"bytes"
	"image/png"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Manager wires TOTP enrollment and verification to caller-provided secret
// loading and storage callbacks.
type Manager struct {
	secret func(identity string) string
	store  func(identity, secret string) error
	issuer string
}

// NewManager creates a TOTP manager for the issuer.
func NewManager(
	issuer string,
	secret func(identity string) string,
	store func(identity, secret string) error,
) (*Manager, error) {
	if secret == nil {
		return nil, errStr("nil secret callback")
	}

	if store == nil {
		return nil, errStr("nil store callback")
	}

	return &Manager{
		secret: secret,
		store:  store,
		issuer: issuer,
	}, nil
}

// Enrollment creates enrollment data for an account.
func (m *Manager) Enrollment(account string) (url string, qrpng []byte, err error) {
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

	if err := m.store(account, key.Secret()); err != nil {
		return "", nil, err
	}

	img, err := key.Image(200, 200)
	if err != nil {
		return "", nil, err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", nil, err
	}

	return key.URL(), buf.Bytes(), nil
}

// Verify checks a passcode for an identity.
func (m *Manager) Verify(identity, passcode string) bool {
	secret := m.secret(identity)
	if secret == "" {
		return false
	}

	return totp.Validate(passcode, secret)
}
