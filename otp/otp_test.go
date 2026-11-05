package otp

import (
	"strings"
	"testing"
)

func TestNewSignerRequiresSecret(t *testing.T) {
	if _, err := NewSigner(""); err == nil {
		t.Fatal("NewSigner() error = nil, want an error for an empty secret")
	}
}

func TestSignIsDeterministicAndContextBound(t *testing.T) {
	signer, err := NewSigner("a sufficiently long and independent HMAC key")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	first := signer.Sign("login", "alice@example.com", "123456")
	second := signer.Sign("login", "alice@example.com", "123456")
	if first != second {
		t.Fatalf("Sign() = %q and %q, want equal digests", first, second)
	}
	if len(first) != 64 || strings.Trim(first, "0123456789abcdef") != "" {
		t.Fatalf("Sign() = %q, want 64 lowercase hexadecimal characters", first)
	}

	differentPurpose := signer.Sign("email_change", "alice@example.com", "123456")
	differentIdentity := signer.Sign("login", "bob@example.com", "123456")
	differentCode := signer.Sign("login", "alice@example.com", "654321")
	for name, digest := range map[string]string{
		"purpose":  differentPurpose,
		"identity": differentIdentity,
		"code":     differentCode,
	} {
		if digest == first {
			t.Fatalf("Sign() did not change when %s changed", name)
		}
	}
}

func TestSignLengthPrefixesFields(t *testing.T) {
	signer, err := NewSigner("a sufficiently long and independent HMAC key")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	first := signer.Sign("ab", "c", "123456")
	second := signer.Sign("a", "bc", "123456")
	if first == second {
		t.Fatal("Sign() produced the same digest for ambiguous field boundaries")
	}
}

func TestVerify(t *testing.T) {
	signer, err := NewSigner("a sufficiently long and independent HMAC key")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	digest := signer.Sign("login", "alice@example.com", "123456")
	if !signer.Verify("login", "alice@example.com", "123456", digest) {
		t.Fatal("Verify() = false for the matching context")
	}
	if signer.Verify("email_change", "alice@example.com", "123456", digest) {
		t.Fatal("Verify() = true for a different purpose")
	}
	if signer.Verify("login", "bob@example.com", "123456", digest) {
		t.Fatal("Verify() = true for a different identity")
	}
	if signer.Verify("login", "alice@example.com", "654321", digest) {
		t.Fatal("Verify() = true for a different code")
	}
	if signer.Verify("login", "alice@example.com", "123456", "not-a-digest") {
		t.Fatal("Verify() = true for an invalid digest")
	}
}
