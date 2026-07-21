package secrets

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"

	"golang.org/x/crypto/scrypt"
)

type errStr string

func (e errStr) Error() string {
	return string(e)
}

func deriveEncryptionKey(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errStr("password required")
	}

	if len(salt) != encryptSaltSize {
		return nil, errStr("invalid salt")
	}

	return scrypt.Key(password, salt, scryptN, scryptR, scryptP, encryptKeySize)
}

func pepperPassword(password, pepper []byte) []byte {
	mac := hmac.New(sha512.New384, pepper)
	mac.Write(password)

	sum := mac.Sum(nil)

	peppered := make([]byte, base64.RawStdEncoding.EncodedLen(len(sum)))
	base64.RawStdEncoding.Encode(peppered, sum)

	return peppered
}
