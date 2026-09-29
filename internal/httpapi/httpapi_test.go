package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestTokenOK(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer expected-token")
	if !tokenOK(req, "expected-token", "Authorization") {
		t.Fatal("expected bearer token to be accepted")
	}
	if tokenOK(req, "different-token", "Authorization") {
		t.Fatal("expected mismatched bearer token to be rejected")
	}
}

func TestEmptyConfiguredTokenIsRejected(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if tokenOK(req, "", "Authorization") {
		t.Fatal("empty configured token must never authorize a request")
	}
}

func TestImageFileNameValidation(t *testing.T) {
	for _, value := range []string{"ubuntu-24.04.qcow2", "rocky_9.raw"} {
		if !imageFileNamePattern.MatchString(value) {
			t.Fatalf("expected valid image file name: %s", value)
		}
	}
	for _, value := range []string{"../ubuntu.qcow2", "/data/image.qcow2", "image name.qcow2"} {
		if imageFileNamePattern.MatchString(value) {
			t.Fatalf("expected invalid image file name: %s", value)
		}
	}
}
