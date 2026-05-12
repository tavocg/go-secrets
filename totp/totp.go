// Package totp is just a wrapper for github.com/pquerna/otp
package totp

import (
	"bytes"
	"image/png"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type totpManager struct {
	secret func(identity string) string
	store  func() error
	issuer string
}

func (i *totpManager) Enrollment(account string) (url string, qrpng []byte, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      i.issuer,
		AccountName: account,
		// Default pquerna/otp/totp.GenerateOpts options
		Period:     30,
		SecretSize: 20,
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
	})
	if err != nil {
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

func (i *totpManager) Verify(identity, passcode string) bool {
	return totp.Validate(passcode, i.secret(identity))
}
