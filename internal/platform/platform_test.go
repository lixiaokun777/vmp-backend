package platform

import (
	"regexp"
	"testing"
)

func TestGeneratePasswordContainsRequiredCharacterGroups(t *testing.T) {
	password, err := generatePassword(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 20 {
		t.Fatalf("unexpected password length: %d", len(password))
	}
	for _, pattern := range []string{`[A-Z]`, `[a-z]`, `[0-9]`} {
		if !regexp.MustCompile(pattern).MatchString(password) {
			t.Fatalf("password does not match %s", pattern)
		}
	}
}

func TestGeneratePasswordRejectsShortLength(t *testing.T) {
	if _, err := generatePassword(8); err == nil {
		t.Fatal("expected short password length to be rejected")
	}
}

func TestDefaultUsername(t *testing.T) {
	if got := defaultUsername("ubuntu"); got != "ubuntu" {
		t.Fatalf("ubuntu username = %s", got)
	}
	if got := defaultUsername("rocky"); got != "cloud-user" {
		t.Fatalf("rocky username = %s", got)
	}
}
