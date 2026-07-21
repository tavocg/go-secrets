package totp

import (
	"bytes"
	"image/png"
	"testing"
)

func TestEnrollmentReturnsNoQRCodeWhenImageSizeIsOmitted(t *testing.T) {
	_, qrpng := enrollment(t)

	if qrpng != nil {
		t.Fatalf("Enrollment() QR PNG length = %d, want nil", len(qrpng))
	}
}

func TestEnrollmentAllowsQRCodeSizeOverride(t *testing.T) {
	_, qrpng := enrollment(t, 256)

	assertPNGSize(t, qrpng, 256)
}

func enrollment(t *testing.T, imageSize ...int) (string, []byte) {
	t.Helper()

	stored := map[string]string{}
	manager, err := NewManager(
		"go-secrets",
		func(identity string) string {
			return stored[identity]
		},
		func(identity, secret string) error {
			stored[identity] = secret
			return nil
		},
	)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	url, qrpng, err := manager.Enrollment("example@example.com", imageSize...)
	if err != nil {
		t.Fatalf("Enrollment() error = %v", err)
	}

	return url, qrpng
}

func assertPNGSize(t *testing.T, qrpng []byte, wantSize int) {
	t.Helper()

	img, err := png.Decode(bytes.NewReader(qrpng))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	bounds := img.Bounds()
	if bounds.Dx() != wantSize || bounds.Dy() != wantSize {
		t.Fatalf("QR PNG size = %dx%d, want %dx%d", bounds.Dx(), bounds.Dy(), wantSize, wantSize)
	}
}
