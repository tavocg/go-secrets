package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	encryptSaltSize = 32
	encryptKeySize  = 32
	scryptN         = 1 << 15
	scryptR         = 8
	scryptP         = 1
)

func Encrypt(plaintext, password, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errStr("aad required")
	}

	key, salt, err := deriveEncryptionKey(password)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, 0, len(salt)+len(plaintext)+gcm.Overhead())
	ciphertext = append(ciphertext, salt...)
	ciphertext = gcm.Seal(ciphertext, nil, plaintext, aad)

	return ciphertext, nil
}

func Decrypt(ciphertext, password, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errStr("aad required")
	}

	if len(ciphertext) < encryptSaltSize {
		return nil, errStr("ciphertext too short")
	}

	salt := ciphertext[:encryptSaltSize]
	encrypted := ciphertext[encryptSaltSize:]

	key, err := deriveEncryptionKeyWithSalt(password, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}

	if len(encrypted) < gcm.Overhead() {
		return nil, errStr("ciphertext too short")
	}

	plaintext, err := gcm.Open(nil, nil, encrypted, aad)
	if err != nil {
		return nil, errStr("authentication failed")
	}

	return plaintext, nil
}

func deriveEncryptionKey(password []byte) (key, salt []byte, err error) {
	if len(password) == 0 {
		return nil, nil, errStr("password required")
	}

	salt = make([]byte, encryptSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}

	key, err = deriveEncryptionKeyWithSalt(password, salt)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func deriveEncryptionKeyWithSalt(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errStr("password required")
	}

	if len(salt) != encryptSaltSize {
		return nil, errStr("invalid salt")
	}

	return scrypt.Key(password, salt, scryptN, scryptR, scryptP, encryptKeySize)
}
