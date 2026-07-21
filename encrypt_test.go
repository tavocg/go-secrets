package secrets

import (
	"bytes"
	"testing"
)

func TestEncryptUsesVersionedCiphertextHeader(t *testing.T) {
	plaintext := []byte("secret payload")
	password := []byte("correct horse battery staple")
	aad := []byte("record:42")

	ciphertext, err := Encrypt(plaintext, password, aad)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	wantHeader := []byte{'G', 'S', 'C', 'T', 1, 1, 1, 0}
	if !bytes.HasPrefix(ciphertext, wantHeader) {
		t.Fatalf("Encrypt() ciphertext header = %x, want prefix %x", ciphertext[:len(wantHeader)], wantHeader)
	}

	decrypted, err := Decrypt(ciphertext, password, aad)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}
