package totp

type errStr string

func (e errStr) Error() string {
	return string(e)
}
