# go-secrets

Small Go helpers for generating secrets, hashing passwords with an application
pepper, encrypting authenticated payloads, and enrolling TOTP credentials.

## Packages

- `github.com/tavocg/go-secrets`: random bytes, hex secrets, numeric OTPs,
  peppered bcrypt hashes, and authenticated encryption.
- `github.com/tavocg/go-secrets/totp`: TOTP enrollment and verification backed by
  caller-provided secret storage.

## Install

```sh
go get github.com/tavocg/go-secrets
go get github.com/tavocg/go-secrets/totp
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

## TOTP Usage

```go
store := map[string]string{}

manager, err := totp.NewManager(
	"example-app",
	func(identity string) string {
		return store[identity]
	},
	func(identity, secret string) error {
		store[identity] = secret
		return nil
	},
)
```

Enrollment always returns an `otpauth://` URL and stores the generated secret.
By default it does not render a QR image:

```go
url, qrpng, err := manager.Enrollment("alice@example.com")
// qrpng == nil
```

Pass an image size to render a square PNG QR code:

```go
url, qrpng, err := manager.Enrollment("alice@example.com", 512)
```

Verify passcodes against the stored secret:

```go
ok := manager.Verify("alice@example.com", "123456")
```

## License

GPL-3.0. See [LICENSE](LICENSE).
