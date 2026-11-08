package totp

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

type errStr string

func (e errStr) Error() string {
	return string(e)
}

func matchingCounter(passcode, secret string, now time.Time) (uint64, bool) {
	if secret == "" || now.Unix() < 0 {
		return 0, false
	}
	current := now.Unix() / 30
	// Choose one counter; callers must not retry after storage rejects it.
	for counter := current + 1; counter >= 0 && counter >= current-1; counter-- {
		valid, err := hotp.ValidateCustom(passcode, uint64(counter), secret, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false
		}
		if valid {
			return uint64(counter), true
		}
	}
	return 0, false
}
