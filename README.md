# go-secrets

Small Go helpers for generating secrets, hashing passwords with an application
pepper, encrypting authenticated payloads, enrolling TOTP credentials, and
storing verification codes as keyed digests.

## Packages

- `github.com/tavocg/go-secrets`: random bytes, hex secrets, numeric OTPs,
  peppered bcrypt hashes, and authenticated encryption.
- `github.com/tavocg/go-secrets/totp/v3`: TOTP enrollment and verification backed
  by caller-provided secret storage and atomic counter consumption.
- `github.com/tavocg/go-secrets/otp`: HMAC-SHA-256 digests for one-time codes,
  bound to purpose and identity.

## Install

```sh
go get github.com/tavocg/go-secrets
go get github.com/tavocg/go-secrets/totp/v3
go get github.com/tavocg/go-secrets/otp
```

## Core Usage

```go
secret, err := secrets.RandStr(256)
otp, err := secrets.RandOTP(6)
hash, err := secrets.Hash([]byte("password"), []byte("application pepper"))
err = secrets.Compare(hash, []byte("password"), []byte("application pepper"))
```

```go
ciphertext, err := secrets.Encrypt(
	[]byte("payload"),
	[]byte("password"),
	[]byte("record:42"),
)
plaintext, err := secrets.Decrypt(ciphertext, []byte("password"), []byte("record:42"))
```

Encryption uses AES-256-GCM with a scrypt-derived key and a versioned `GSCT`
envelope carrying a random salt and nonce. Application-provided associated
data (AAD) is also authenticated. Both password and AAD must be nonempty.
Version 1 ciphertexts retain their format and remain readable after upgrades
to the shared cipher setup.

Use `errors.Is` with `ErrAADRequired`, `ErrPasswordRequired`,
`ErrCiphertextTooShort`, `ErrUnsupportedCiphertextFormat`, or
`ErrAuthenticationFailed` to handle failures. Unsupported headers and inputs
shorter than the envelope minimum are rejected before password derivation.
A wrong password, wrong AAD, or modified encrypted payload returns
`ErrAuthenticationFailed` without plaintext.

## TOTP Usage

Import `github.com/tavocg/go-secrets/totp/v3`. Supply the five callbacks in
`totp.Storage` from your application's credential storage adapter. The method
names below are illustrative; their signatures are defined in
[`totp/storage.go`](totp/storage.go).

```go
manager, err := totp.NewManager("example-app", totp.Storage{
    Secret:       credentials.LoadActiveSecret,
    Consume:      credentials.ConsumeCounter,
    Pending:      credentials.LoadPending,
    StorePending: credentials.SavePending,
    Activate:     credentials.ActivatePending,
})
```

Use durable, shared storage for active credentials, consumed counters, and
pending enrollments. Every verifier must use the same storage. Callbacks must
be safe for concurrent calls and fail closed on storage errors.

Enrollment returns an `otpauth://` URL and saves a pending secret with a
five-minute expiration. It leaves the active secret and its consumed counter
unchanged. By default no QR image is rendered; pass a size to obtain a square
PNG:

```go
url, qrpng, err := manager.Enrollment("alice@example.com") // qrpng == nil
url, qrpng, err = manager.Enrollment("alice@example.com", 512)
```

After the user scans the QR code, confirm a code from that authenticator:

```go
ok := manager.ConfirmEnrollment("alice@example.com", passcode)
```

Confirmation loads the pending secret from storage for that identity. It does
not accept an enrollment secret from the client. `Activate` must perform all
of the following in one transaction or equivalent conditional write:

1. Check that the pending secret still matches, has not expired, and belongs
   to the current active credential generation (including the initial state
   with no active credential).
2. Replace the active secret and store the matched counter as already consumed.
3. Delete the pending enrollment and return true only after commit.

A concurrent confirmation has only one winner. Replacing a pending enrollment
invalidates older confirmations; changing the active credential also
invalidates pending enrollments created for its previous generation. Failed
confirmation attempts must leave the active credential unchanged and must not
extend the pending expiration. Clean up expired pending records in storage.

Normal verification reads only the active secret and consumes its counter:

```go
ok := manager.Verify("alice@example.com", passcode)
```

The confirmation code is already consumed when `ConfirmEnrollment` succeeds.
`Consume` must atomically check that the loaded secret is still active and
advance its last accepted counter only when the new counter is higher. For
example, using your driver's parameter syntax:

```sql
UPDATE totp_credentials
SET last_counter = :counter
WHERE identity = :identity AND secret = :secret
  AND (last_counter IS NULL OR last_counter < :counter);
```

Return true only when one row changes and the write commits. Both verification
and confirmation retain six-digit SHA-1 codes and one 30-second interval of
clock skew in either direction. Use authenticated, recently reauthenticated
account identities for enrollment changes, throttle confirmation and
verification attempts, and avoid logging secrets or provisioning URLs.

### Migrating from v2

Change the import path to `/v3` and construct `totp.Storage` with the existing
secret-loading and consumption callbacks plus the three enrollment callbacks.
Replace the old active-secret storage callback with separate pending storage
and atomic activation. Add pending-secret, expiration, and credential-generation
storage; preserve existing active secrets and last accepted counters. Stop old
writers before enabling the new flow. An in-memory reference implementation of
the storage contract is in [`totp/replay_test.go`](totp/replay_test.go).

When migrating from v1, also persist the last accepted counter. Old acceptance
history is unavailable: let the old validation window expire before serving
requests through the new verifier.

## OTP Usage

`otp.Signer` produces keyed digests for challenge codes that are generated by
the application. Bind each digest to its purpose and identity so the same code
cannot be replayed across flows or accounts.

```go
signer, err := otp.NewSigner("independent 32-byte random secret")

digest := signer.Sign("login", "alice@example.com", "123456")
ok := signer.Verify("login", "alice@example.com", "123456", digest)
```

Store only `digest`. Plaintext codes are easy to enumerate if a six-digit code
is stored as an unkeyed hash. Keep the HMAC key independent from JWT or session
signing keys and rotate it deliberately: changing the key invalidates every
pending digest.

## License

GPL-3.0. See [LICENSE](LICENSE).
