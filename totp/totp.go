// Package totp provides TOTP enrollment and verification with atomic consumption.
package totp

import (
	"bytes"
	"image/png"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Manager wires TOTP enrollment and verification to caller-provided storage.
type Manager struct {
	storage Storage
	issuer  string
}

// NewManager creates a TOTP manager for the issuer.
func NewManager(issuer string, storage Storage) (*Manager, error) {
	if storage.Secret == nil {
		return nil, errStr("nil secret callback")
	}
	if storage.Consume == nil {
		return nil, errStr("nil consume callback")
	}
	if storage.Pending == nil {
		return nil, errStr("nil pending callback")
	}
	if storage.StorePending == nil {
		return nil, errStr("nil store pending callback")
	}
	if storage.Activate == nil {
		return nil, errStr("nil activate callback")
	}

	return &Manager{
		storage: storage,
		issuer:  issuer,
	}, nil
}

// Enrollment creates pending enrollment data valid for five minutes. It leaves
// the active credential unchanged until ConfirmEnrollment succeeds.
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
	if err := m.storage.StorePending(account, key.Secret(), time.Now().Add(5*time.Minute)); err != nil {
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
	if identity == "" {
		return false
	}
	secret := m.storage.Secret(identity)
	counter, valid := matchingCounter(passcode, secret, now)
	return valid && m.storage.Consume(identity, secret, counter)
}

// ConfirmEnrollment validates a pending enrollment's code and atomically
// activates the credential with that code already consumed.
func (m *Manager) ConfirmEnrollment(identity, passcode string) bool {
	return m.confirmAt(identity, passcode, time.Now())
}

func (m *Manager) confirmAt(identity, passcode string, now time.Time) bool {
	if identity == "" {
		return false
	}
	secret, expiresAt := m.storage.Pending(identity)
	if !now.Before(expiresAt) {
		return false
	}
	counter, valid := matchingCounter(passcode, secret, now)
	return valid && m.storage.Activate(identity, secret, counter)
}
