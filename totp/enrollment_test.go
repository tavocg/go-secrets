package totp

import (
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnrollmentPreservesActiveSecret(t *testing.T) {
	s := &testStore{data: map[string]testCredential{"alice": {secret: testSecret}}}
	m := newTestManager(t, s)
	if _, _, err := m.Enrollment("alice"); err != nil {
		t.Fatal(err)
	}
	if got := s.secret("alice"); got != testSecret {
		t.Fatal("enrollment replaced the active secret before confirmation")
	}
}

func enrollSecret(t *testing.T, m *Manager, identity string) string {
	t.Helper()
	link, _, err := m.Enrollment(identity)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	secret := parsed.Query().Get("secret")
	if secret == "" {
		t.Fatal("enrollment URL has no secret")
	}
	return secret
}

func TestConfirmEnrollmentActivatesAndConsumesCode(t *testing.T) {
	for _, active := range []string{"", testSecret} {
		s := &testStore{data: map[string]testCredential{"alice": {secret: active, last: 42, used: true}}}
		m := newTestManager(t, s)
		before := s.data["alice"]
		started := time.Now()
		secret := enrollSecret(t, m, "alice")
		_, expiresAt := s.loadPending("alice")
		if expiresAt.Before(started.Add(5*time.Minute)) || expiresAt.After(time.Now().Add(5*time.Minute)) {
			t.Fatal("pending enrollment did not receive a five-minute lifetime")
		}
		if s.data["alice"] != before {
			t.Fatal("enrollment changed the active credential or consumed counter")
		}
		code := codeAt(t, secret, time.Now())
		if !m.ConfirmEnrollment("alice", code) {
			t.Fatal("valid enrollment confirmation rejected")
		}
		if s.secret("alice") != secret || !s.data["alice"].used {
			t.Fatal("confirmed credential was not activated with its counter consumed")
		}
		if pending, _ := s.loadPending("alice"); pending != "" {
			t.Fatal("confirmed enrollment was retained")
		}
		if m.ConfirmEnrollment("alice", code) || m.Verify("alice", code) {
			t.Fatal("confirmation code could be reused")
		}
	}
}

func TestConfirmEnrollmentFailsClosed(t *testing.T) {
	for _, scenario := range []string{"invalid code", "unknown identity", "empty identity", "expired", "expiry boundary", "activation failure"} {
		t.Run(scenario, func(t *testing.T) {
			s := &testStore{data: map[string]testCredential{"alice": {secret: testSecret}}}
			m := newTestManager(t, s)
			secret := enrollSecret(t, m, "alice")
			now := time.Now()
			code, identity := codeAt(t, secret, now), "alice"
			switch scenario {
			case "invalid code":
				code = "invalid"
			case "unknown identity":
				identity = "bob"
			case "empty identity":
				identity = ""
			case "expired":
				s.storePending("alice", secret, now.Add(-time.Second))
			case "expiry boundary":
				s.storePending("alice", secret, now)
			case "activation failure":
				m.storage.Activate = func(string, string, uint64) bool { return false }
			}
			_, expiresAt := s.loadPending("alice")
			if m.confirmAt(identity, code, now) {
				t.Fatal("invalid enrollment confirmation accepted")
			}
			if s.secret("alice") != testSecret {
				t.Fatal("failed confirmation changed the active credential")
			}
			if _, after := s.loadPending("alice"); after != expiresAt {
				t.Fatal("failed confirmation extended or removed the pending enrollment")
			}
		})
	}
}

func TestConcurrentEnrollmentConfirmationHasOneWinner(t *testing.T) {
	s := &testStore{data: map[string]testCredential{"alice": {secret: testSecret}}}
	managers := []*Manager{newTestManager(t, s), newTestManager(t, s)}
	secret := enrollSecret(t, managers[0], "alice")
	code := codeAt(t, secret, time.Now())
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 64 {
		wg.Go(func() {
			<-start
			if managers[i%len(managers)].ConfirmEnrollment("alice", code) {
				successes.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful activations = %d, want 1", got)
	}
}

func TestConfirmationRejectsStorageChangesAfterLoadingPending(t *testing.T) {
	for _, scenario := range []string{"pending replaced", "pending expired", "active replaced"} {
		t.Run(scenario, func(t *testing.T) {
			s := &testStore{data: map[string]testCredential{"alice": {secret: testSecret}}}
			m := newTestManager(t, s)
			secret := enrollSecret(t, m, "alice")
			const replacement = "KRSXG5DSNFXGOIDB"
			m.storage.Pending = func(identity string) (string, time.Time) {
				pending, expiry := s.loadPending(identity)
				switch scenario {
				case "pending replaced":
					s.storePending(identity, replacement, expiry)
				case "pending expired":
					s.storePending(identity, pending, time.Now().Add(-time.Second))
				case "active replaced":
					s.store(identity, replacement)
				}
				return pending, expiry
			}
			if m.ConfirmEnrollment("alice", codeAt(t, secret, time.Now())) {
				t.Fatal("stale enrollment activated after storage changed")
			}
			want := testSecret
			if scenario == "active replaced" {
				want = replacement
			}
			if s.secret("alice") != want {
				t.Fatal("failed confirmation overwrote the current credential")
			}
		})
	}
}

func TestEnrollmentFailurePreservesActiveCredential(t *testing.T) {
	for _, scenario := range []string{"QR failure", "storage failure"} {
		t.Run(scenario, func(t *testing.T) {
			s := &testStore{data: map[string]testCredential{"alice": {secret: testSecret}}}
			m := newTestManager(t, s)
			var size []int
			if scenario == "QR failure" {
				size = []int{1}
			} else {
				m.storage.StorePending = func(string, string, time.Time) error { return errors.New("storage failed") }
			}
			link, image, err := m.Enrollment("alice", size...)
			if err == nil || link != "" || image != nil {
				t.Fatal("failed enrollment returned usable provisioning data")
			}
			if s.secret("alice") != testSecret {
				t.Fatal("failed enrollment modified the active credential")
			}
			if pending, _ := s.loadPending("alice"); pending != "" {
				t.Fatal("failed enrollment unexpectedly stored a pending secret")
			}
		})
	}
}
