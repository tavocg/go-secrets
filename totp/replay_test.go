package totp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	codes "github.com/pquerna/otp/totp"
)

const testSecret = "JBSWY3DPEHPK3PXP"

type testCredential struct {
	secret string
	last   uint64
	used   bool
}

type testStore struct {
	mu   sync.Mutex
	data map[string]testCredential
}

func (s *testStore) secret(identity string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[identity].secret
}

func (s *testStore) store(identity, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[identity].secret != secret {
		s.data[identity] = testCredential{secret: secret}
	}
	return nil
}

func (s *testStore) consume(identity, secret string, counter uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data[identity]
	if c.secret != secret || (c.used && counter <= c.last) {
		return false
	}
	c.last, c.used = counter, true
	s.data[identity] = c
	return true
}

func newTestManager(t *testing.T, s *testStore) *Manager {
	t.Helper()
	m, err := NewManager("example", s.secret, s.store, s.consume)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func codeAt(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := codes.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestVerifyConsumesCodeOnce(t *testing.T) {
	s := &testStore{data: map[string]testCredential{"alice": {secret: testSecret}}}
	m := newTestManager(t, s)
	code := codeAt(t, testSecret, time.Now())
	if !m.Verify("alice", code) {
		t.Fatal("first verification failed")
	}
	if m.Verify("alice", code) {
		t.Fatal("the same code was accepted twice")
	}
	if newTestManager(t, s).Verify("alice", code) {
		t.Fatal("a new manager accepted an already consumed code")
	}
}

func TestVerifyConcurrentManagersConsumeOnce(t *testing.T) {
	s := &testStore{data: map[string]testCredential{"alice": {secret: testSecret}}}
	managers := []*Manager{newTestManager(t, s), newTestManager(t, s)}
	now := time.Unix(1800000015, 0)
	code := codeAt(t, testSecret, now)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := range 64 {
		wg.Go(func() {
			<-start
			if managers[i%len(managers)].verifyAt("alice", code, now) {
				successes.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful verifications = %d, want 1", got)
	}
}

func TestVerifyMatchesCounterAndRejectsReplayAcrossWindows(t *testing.T) {
	now := time.Unix(1800000015, 0)
	for _, offset := range []int{-2, -1, 0, 1, 2} {
		s := &testStore{data: map[string]testCredential{"alice": {secret: testSecret}}}
		m := newTestManager(t, s)
		issued := now.Add(time.Duration(offset) * 30 * time.Second)
		code := codeAt(t, testSecret, issued)
		want := offset >= -1 && offset <= 1
		if got := m.verifyAt("alice", code, now); got != want {
			t.Fatalf("offset %d: verified = %v, want %v", offset, got, want)
		}
		if want && s.data["alice"].last != uint64(issued.Unix()/30) {
			t.Fatalf("offset %d: stored the receiving counter instead of the matched counter", offset)
		}
		if want && m.verifyAt("alice", code, now.Add(30*time.Second)) {
			t.Fatalf("offset %d: expired or consumed code was accepted in the next window", offset)
		}
	}
}

func TestVerifyRejectsOlderCountersAndAllowsOtherIdentities(t *testing.T) {
	s := &testStore{data: map[string]testCredential{
		"alice": {secret: testSecret}, "bob": {secret: testSecret},
	}}
	m := newTestManager(t, s)
	now := time.Unix(1800000015, 0)
	future := codeAt(t, testSecret, now.Add(30*time.Second))
	if !m.verifyAt("alice", future, now) {
		t.Fatal("valid future-skew code rejected")
	}
	if m.verifyAt("alice", codeAt(t, testSecret, now), now) {
		t.Fatal("older counter accepted after a newer one")
	}
	if !m.verifyAt("bob", future, now) {
		t.Fatal("another identity's code rejected")
	}
	next := codeAt(t, testSecret, now.Add(60*time.Second))
	if !m.verifyAt("alice", next, now.Add(30*time.Second)) {
		t.Fatal("new counter rejected")
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	now := time.Unix(1800000015, 0)
	code := codeAt(t, testSecret, now)
	calls := 0
	m, err := NewManager("example", func(identity string) string {
		if identity == "alice" {
			return testSecret
		}
		return ""
	}, func(string, string) error { return nil }, func(string, string, uint64) bool {
		calls++
		return false
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.verifyAt("alice", "invalid", now) || m.verifyAt("unknown", code, now) || m.verifyAt("", code, now) {
		t.Fatal("invalid input accepted")
	}
	if calls != 0 {
		t.Fatal("invalid input reached the consumption callback")
	}
	if m.verifyAt("alice", code, now) || calls != 1 {
		t.Fatal("consumption failure did not reject the code")
	}
}

func TestVerifyRejectsSecretChangedBeforeConsumption(t *testing.T) {
	s := &testStore{data: map[string]testCredential{"alice": {secret: testSecret}}}
	const replacement = "KRSXG5DSNFXGOIDB"
	m, err := NewManager("example", func(identity string) string {
		old := s.secret(identity)
		s.store(identity, replacement)
		return old
	}, s.store, s.consume)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000015, 0)
	if m.verifyAt("alice", codeAt(t, testSecret, now), now) {
		t.Fatal("code accepted after its secret was replaced")
	}
	if !m.verifyAt("alice", codeAt(t, replacement, now), now) {
		t.Fatal("new credential's code rejected")
	}
}

func TestNewManagerRequiresCallbacks(t *testing.T) {
	secret := func(string) string { return testSecret }
	store := func(string, string) error { return nil }
	consume := func(string, string, uint64) bool { return false }
	for _, missing := range []string{"secret", "store", "consume"} {
		t.Run(missing, func(t *testing.T) {
			load, save, use := secret, store, ConsumeFunc(consume)
			switch missing {
			case "secret":
				load = nil
			case "store":
				save = nil
			case "consume":
				use = nil
			}
			if _, err := NewManager("example", load, save, use); err == nil {
				t.Fatal("nil callback accepted")
			}
		})
	}
}
