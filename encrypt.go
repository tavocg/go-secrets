package secrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

const (
	ciphertextMagic                    = "GSCT"
	ciphertextVersion                  = byte(1)
	ciphertextKDFScrypt                = byte(1)
	ciphertextAEADAES256GCMRandomNonce = byte(1)
	ciphertextHeaderSize               = 8

	encryptSaltSize = 32
	encryptKeySize  = 32
	scryptN         = 1 << 15
	scryptR         = 8
	scryptP         = 1
)

var ciphertextHeaderV1 = [ciphertextHeaderSize]byte{
	ciphertextMagic[0], ciphertextMagic[1], ciphertextMagic[2], ciphertextMagic[3],
	ciphertextVersion,
	ciphertextKDFScrypt,
	ciphertextAEADAES256GCMRandomNonce,
	0,
}

func Encrypt(plaintext, password, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errStr("aad required")
	}

	salt := make([]byte, encryptSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := deriveEncryptionKey(password, salt)
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

	authData := encryptAAD(ciphertextHeaderV1[:], aad)
	ciphertext := make([]byte, 0, ciphertextHeaderSize+len(salt)+len(plaintext)+gcm.Overhead())
	ciphertext = append(ciphertext, ciphertextHeaderV1[:]...)
	ciphertext = append(ciphertext, salt...)
	ciphertext = gcm.Seal(ciphertext, nil, plaintext, authData)

	return ciphertext, nil
}

func Decrypt(ciphertext, password, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errStr("aad required")
	}

	if len(ciphertext) < ciphertextHeaderSize+encryptSaltSize {
		return nil, errStr("ciphertext too short")
	}

	header := ciphertext[:ciphertextHeaderSize]
	if !bytes.Equal(header, ciphertextHeaderV1[:]) {
		return nil, errStr("unsupported ciphertext format")
	}

	saltStart := ciphertextHeaderSize
	saltEnd := saltStart + encryptSaltSize
	salt := ciphertext[saltStart:saltEnd]
	encrypted := ciphertext[saltEnd:]

	key, err := deriveEncryptionKey(password, salt)
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

	authData := encryptAAD(header, aad)
	plaintext, err := gcm.Open(nil, nil, encrypted, authData)
	if err != nil {
		return nil, errStr("authentication failed")
	}

	return plaintext, nil
}

func encryptAAD(header, aad []byte) []byte {
	authData := make([]byte, 0, len(header)+len(aad))
	authData = append(authData, header...)
	authData = append(authData, aad...)
	return authData
}
