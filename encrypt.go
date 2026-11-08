package secrets

import (
	"bytes"
	"crypto/rand"
	"io"
)

const (
	ErrAADRequired                 errStr = "aad required"
	ErrPasswordRequired            errStr = "password required"
	ErrCiphertextTooShort          errStr = "ciphertext too short"
	ErrUnsupportedCiphertextFormat errStr = "unsupported ciphertext format"
	ErrAuthenticationFailed        errStr = "authentication failed"
)

const (
	ciphertextMagic                    = "GSCT"
	ciphertextVersion                  = byte(1)
	ciphertextKDFScrypt                = byte(1)
	ciphertextAEADAES256GCMRandomNonce = byte(1)
	ciphertextHeaderSize               = 8

	// Version 1 stores a 12-byte random nonce and a 16-byte GCM tag.
	encryptOverhead = 12 + 16
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

// Encrypt uses AES-256-GCM with a scrypt-derived key, a random salt, and a
// random nonce. Both password and associated data must be nonempty.
func Encrypt(plaintext, password, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}

	salt := make([]byte, encryptSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	gcm, err := newEncryptionAEAD(password, salt)
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

// Decrypt authenticates and decrypts a versioned ciphertext. Authentication
// failures return ErrAuthenticationFailed without plaintext.
func Decrypt(ciphertext, password, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, ErrAADRequired
	}

	if len(ciphertext) < ciphertextHeaderSize+encryptSaltSize+encryptOverhead {
		return nil, ErrCiphertextTooShort
	}

	header := ciphertext[:ciphertextHeaderSize]
	if !bytes.Equal(header, ciphertextHeaderV1[:]) {
		return nil, ErrUnsupportedCiphertextFormat
	}

	saltStart := ciphertextHeaderSize
	saltEnd := saltStart + encryptSaltSize
	salt := ciphertext[saltStart:saltEnd]
	encrypted := ciphertext[saltEnd:]

	gcm, err := newEncryptionAEAD(password, salt)
	if err != nil {
		return nil, err
	}

	authData := encryptAAD(header, aad)
	plaintext, err := gcm.Open(nil, nil, encrypted, authData)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}

	return plaintext, nil
}

func encryptAAD(header, aad []byte) []byte {
	authData := make([]byte, 0, len(header)+len(aad))
	authData = append(authData, header...)
	authData = append(authData, aad...)
	return authData
}
