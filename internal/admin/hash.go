package admin

func HashPassword(pw string) (string, error) {
	return hashPassword(pw)
}

func VerifyPassword(stored, pw string) bool {
	return verifyPassword(stored, pw)
}

func DummyHash() string {
	return dummy()
}
