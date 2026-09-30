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

func TestTerminalFailureStatus(t *testing.T) {
	cases := map[string]string{
		"CREATE_INSTANCE":         "ERROR",
		"START_INSTANCE":          "STOPPED",
		"STOP_INSTANCE":           "RUNNING",
		"REBOOT_INSTANCE":         "RUNNING",
		"DELETE_INSTANCE":         "RETAINED",
		"RESET_INSTANCE_PASSWORD": "RUNNING",
	}
	for taskType, expected := range cases {
		if got := terminalFailureStatus(taskType); got != expected {
			t.Fatalf("%s failure status = %s, want %s", taskType, got, expected)
		}
	}
}
