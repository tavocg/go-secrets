package secrets

import (
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashRequiresPepper(t *testing.T) {
	if _, err := Hash([]byte("password"), nil, bcrypt.MinCost); !errors.Is(err, ErrPepperRequired) {
		t.Fatalf("Hash() error = %v, want %v", err, ErrPepperRequired)
	}
}

func TestCompareRequiresPepper(t *testing.T) {
	if err := Compare([]byte("hash"), []byte("password"), nil); !errors.Is(err, ErrPepperRequired) {
		t.Fatalf("Compare() error = %v, want %v", err, ErrPepperRequired)
	}
}

func TestHashCompare(t *testing.T) {
	password := []byte("password")
	pepper := []byte("application secret pepper")

	hash, err := Hash(password, pepper, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if err := Compare(hash, password, pepper); err != nil {
		t.Fatalf("Compare() error = %v", err)
	}

	if err := Compare(hash, password, []byte("wrong pepper")); err == nil {
		t.Fatal("Compare() with wrong pepper error = nil, want error")
	}
}
