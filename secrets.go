// Package secrets implements helper functions for generating secrets.
package secrets

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/bcrypt"
)

const (
	ErrUnevenEntropyBits errStr = "uneven entropy bits"
	ErrOTPLength         errStr = "otp length must be between 1 and 18"
)

// RandBytes returns cryptographically secure random bytes.
func RandBytes(n ...int) ([]byte, error) {
	size := 32
	if len(n) > 0 && n[0] > 0 {
		size = n[0]
	}

	b := make([]byte, size)

	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// RandStr returns a hex-encoded secret with the requested entropy.
func RandStr(entropyBits ...int) (string, error) {
	bits := 256
	if len(entropyBits) > 0 && entropyBits[0] > 0 {
		bits = entropyBits[0]
	}

	if bits%8 != 0 {
		return "", ErrUnevenEntropyBits
	}

	buf, err := RandBytes(bits / 8)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

// RandOTP returns a zero-padded numeric one-time password.
func RandOTP(lengths ...int) (string, error) {
	length := 6
	if len(lengths) > 0 {
		length = lengths[0]
	}

	if length <= 0 || 18 < length {
		return "", ErrOTPLength
	}

	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)

	value, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%0*s", length, value.String()), nil
}

// Hash is pretty much an alias to bcrypt.GenerateFromPassword
func Hash(password []byte, cost ...int) (hash []byte, err error) {
	c := bcrypt.DefaultCost
	if len(cost) > 0 {
		c = cost[0]
	}
	return bcrypt.GenerateFromPassword(password, c)
}

func Pepper(password, pepper []byte) []byte {
	mac := hmac.New(sha512.New384, pepper)
	mac.Write(password)

	sum := mac.Sum(nil)

	peppered := make([]byte, base64.RawStdEncoding.EncodedLen(len(sum)))
	base64.RawStdEncoding.Encode(peppered, sum)

	return peppered
}

func PepperAndHash(password, pepper []byte, cost ...int) ([]byte, error) {
	peppered := Pepper(password, pepper)
	return Hash(peppered, cost...)
}

// CompareHashAndPassword is pretty much an alias to
// bcrypt.CompareHashAndPassword, with pepper functionality
func CompareHashAndPassword(hashedPassword, password []byte, pepper ...[]byte) error {
	if len(pepper) > 0 {
		password = Pepper(password, pepper[0])
	}
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}
