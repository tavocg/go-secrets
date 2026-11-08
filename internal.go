package secrets

import (
	"crypto/aes"
	"crypto/cipher"
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
		return nil, ErrPasswordRequired
	}

	if len(salt) != encryptSaltSize {
		return nil, errStr("invalid salt")
	}

	return scrypt.Key(password, salt, scryptN, scryptR, scryptP, encryptKeySize)
}

func newEncryptionAEAD(password, salt []byte) (cipher.AEAD, error) {
	key, err := deriveEncryptionKey(password, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func pepperPassword(password, pepper []byte) []byte {
	mac := hmac.New(sha512.New384, pepper)
	mac.Write(password)

	sum := mac.Sum(nil)

	peppered := make([]byte, base64.RawStdEncoding.EncodedLen(len(sum)))
	base64.RawStdEncoding.Encode(peppered, sum)

	return peppered
}
