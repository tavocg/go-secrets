package secrets

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// Produced by the pre-refactor v1 implementation using synthetic fixture data.
const legacyCiphertextHex = "4753435401010100c98c8069a8140985ff9a4729450cf17127b04eab7a651f171f1e6f5cee02666e4c30063c1fe6204479e2a38b5e9eae98611e1e6ec0fd902e89c51ab0e50155f292c243ffbd1442ce08f968e0e2b52a2a810c682d20"

func legacyCiphertext(t *testing.T) []byte {
	t.Helper()
	data, err := hex.DecodeString(legacyCiphertextHex)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEncryptionInputErrors(t *testing.T) {
	password, aad := []byte("fixture password"), []byte("record:fixture")
	for _, tt := range []struct {
		name string
		run  func() ([]byte, error)
		want error
	}{
		{"encrypt without aad", func() ([]byte, error) { return Encrypt(nil, password, nil) }, ErrAADRequired},
		{"encrypt without password", func() ([]byte, error) { return Encrypt(nil, nil, aad) }, ErrPasswordRequired},
		{"decrypt without aad", func() ([]byte, error) { return Decrypt(nil, nil, nil) }, ErrAADRequired},
		{"decrypt without password", func() ([]byte, error) { return Decrypt(legacyCiphertext(t), nil, aad) }, ErrPasswordRequired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if output, err := tt.run(); !errors.Is(err, tt.want) || output != nil {
				t.Fatalf("output = %x, error = %v, want nil, %v", output, err, tt.want)
			}
		})
	}
}

func TestDecryptRejectsTooShortCiphertextBeforePasswordDerivation(t *testing.T) {
	fixture := legacyCiphertext(t)
	for _, length := range []int{0, 1, 7, 8, 39, 40, 67} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			output, err := Decrypt(fixture[:length], nil, []byte("record:fixture"))
			if !errors.Is(err, ErrCiphertextTooShort) || output != nil {
				t.Fatalf("length %d: output = %x, error = %v, want nil, ErrCiphertextTooShort", length, output, err)
			}
		})
	}
}

func TestDecryptRejectsTruncatedPayload(t *testing.T) {
	fixture := legacyCiphertext(t)
	for _, length := range []int{68, len(fixture) - 1} {
		output, err := Decrypt(fixture[:length], []byte("fixture password"), []byte("record:fixture"))
		if !errors.Is(err, ErrAuthenticationFailed) || output != nil {
			t.Fatalf("length %d: output = %x, error = %v, want nil, ErrAuthenticationFailed", length, output, err)
		}
	}
}

func TestDecryptRejectsUnsupportedHeaderBeforePasswordDerivation(t *testing.T) {
	for i := 0; i < 8; i++ {
		ciphertext := legacyCiphertext(t)
		ciphertext[i] ^= 1
		output, err := Decrypt(ciphertext, nil, []byte("record:fixture"))
		if !errors.Is(err, ErrUnsupportedCiphertextFormat) || output != nil {
			t.Fatalf("header byte %d: output = %x, error = %v, want nil, ErrUnsupportedCiphertextFormat", i, output, err)
		}
	}
}

func TestDecryptAuthenticationFailuresReturnNoPlaintext(t *testing.T) {
	for _, tt := range []struct {
		name, password, aad string
		index               int
	}{
		{"wrong password", "wrong password", "record:fixture", -1},
		{"wrong aad", "fixture password", "record:other", -1},
		{"changed salt", "fixture password", "record:fixture", 8},
		{"changed nonce", "fixture password", "record:fixture", 40},
		{"changed ciphertext", "fixture password", "record:fixture", 52},
		{"changed tag", "fixture password", "record:fixture", len(legacyCiphertextHex)/2 - 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext := legacyCiphertext(t)
			if tt.index >= 0 {
				ciphertext[tt.index] ^= 1
			}
			output, err := Decrypt(ciphertext, []byte(tt.password), []byte(tt.aad))
			if !errors.Is(err, ErrAuthenticationFailed) || output != nil {
				t.Fatalf("output = %x, error = %v, want nil, ErrAuthenticationFailed", output, err)
			}
		})
	}
}

func TestEncryptionEmptyPlaintextRoundTrip(t *testing.T) {
	password, aad := []byte("fixture password"), []byte("record:empty")
	ciphertext, err := Encrypt(nil, password, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != 68 {
		t.Fatalf("empty plaintext ciphertext has %d bytes, want 68", len(ciphertext))
	}
	plaintext, err := Decrypt(ciphertext, password, aad)
	if err != nil || len(plaintext) != 0 {
		t.Fatalf("empty round trip = %x, %v", plaintext, err)
	}
}

func TestDecryptPreviousCiphertext(t *testing.T) {
	plaintext, err := Decrypt(legacyCiphertext(t), []byte("fixture password"), []byte("record:fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, []byte("legacy ciphertext fixture")) {
		t.Fatalf("previous ciphertext decrypted to %q", plaintext)
	}
}
