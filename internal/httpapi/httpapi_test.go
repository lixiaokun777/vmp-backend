package httpapi

import (
	"net/http"
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

func TestPasswordPolicy(t *testing.T) {
	if err := validatePassword("StrongPass123"); err != nil {
		t.Fatalf("valid password was rejected: %v", err)
	}
	for _, password := range []string{"short1A", "onlylowercase1", "ONLYUPPERCASE1", "NoDigitsHere"} {
		if validatePassword(password) == nil {
			t.Fatalf("invalid password was accepted: %s", password)
		}
	}
}

func TestLDAPConfigurationValidation(t *testing.T) {
	valid := LDAPConfig{Active: true, URL: "ldaps://ldap.example.com:636", BaseDN: "dc=example,dc=com", LoginFilter: "(uid=%s)", SyncFilter: "(objectClass=person)", UsernameAttr: "uid", DisplayNameAttr: "cn", EmailAttr: "mail"}
	if err := validateLDAPConfig(valid); err != nil {
		t.Fatalf("valid LDAP configuration was rejected: %v", err)
	}
	invalid := valid
	invalid.LoginFilter = "(uid=missing-placeholder)"
	if validateLDAPConfig(invalid) == nil {
		t.Fatal("LDAP login filter without placeholder was accepted")
	}
}

func TestLDAPSecretEncryption(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	ciphertext, err := encryptSecret(key, []byte("directory-password"))
	if err != nil {
		t.Fatalf("LDAP secret encryption failed: %v", err)
	}
	plaintext, err := decryptSecret(key, ciphertext)
	if err != nil || string(plaintext) != "directory-password" {
		t.Fatalf("LDAP secret decryption failed: %v", err)
	}
	if string(ciphertext) == "directory-password" {
		t.Fatal("LDAP secret was not encrypted")
	}
}

func TestOrdinaryUserRoutePolicy(t *testing.T) {
	allowed := []*http.Request{
		httptest.NewRequest("GET", "/api/v1/flavors", nil),
		httptest.NewRequest("POST", "/api/v1/applications", nil),
		httptest.NewRequest("GET", "/api/v1/instances?all=1", nil),
		httptest.NewRequest("GET", "/api/v1/instances/00000000-0000-0000-0000-000000000000", nil),
		httptest.NewRequest("POST", "/api/v1/instances/00000000-0000-0000-0000-000000000000/actions", nil),
		httptest.NewRequest("POST", "/api/v1/instances/00000000-0000-0000-0000-000000000000/renew", nil),
		httptest.NewRequest("POST", "/api/v1/instances/00000000-0000-0000-0000-000000000000/restore", nil),
		httptest.NewRequest("GET", "/api/v1/approvals?scope=mine", nil),
		httptest.NewRequest("POST", "/api/v1/approvals/00000000-0000-0000-0000-000000000000/withdraw", nil),
		httptest.NewRequest("POST", "/api/v1/approvals/00000000-0000-0000-0000-000000000000/resubmit-short", nil),
	}
	for _, request := range allowed {
		if !ordinaryUserRouteAllowed(request) {
			t.Fatalf("ordinary user route should be allowed: %s %s", request.Method, request.URL.Path)
		}
	}
	denied := []*http.Request{
		httptest.NewRequest("GET", "/api/v1/summary", nil),
		httptest.NewRequest("GET", "/api/v1/hosts", nil),
		httptest.NewRequest("GET", "/api/v1/users", nil),
		httptest.NewRequest("POST", "/api/v1/networks", nil),
		httptest.NewRequest("POST", "/api/v1/instances/00000000-0000-0000-0000-000000000000/admin-operation", nil),
		httptest.NewRequest("POST", "/api/v1/approvals/00000000-0000-0000-0000-000000000000/decision", nil),
		httptest.NewRequest("POST", "/api/v1/approvals/batch-decision", nil),
	}
	for _, request := range denied {
		if ordinaryUserRouteAllowed(request) {
			t.Fatalf("ordinary user route should be denied: %s %s", request.Method, request.URL.Path)
		}
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

func TestValidateNetworkInput(t *testing.T) {
	valid := networkInput{Name: "研发网络", CIDR: "10.200.8.0/22", Gateway: "10.200.11.254", DNSServers: []string{"10.200.1.10"}, Bridge: "br0", RangeStart: "10.200.9.130", RangeEnd: "10.200.9.150"}
	if err := validateNetworkInput(valid); err != nil {
		t.Fatalf("valid network was rejected: %v", err)
	}
	invalidGateway := valid
	invalidGateway.Gateway = "10.201.1.1"
	if err := validateNetworkInput(invalidGateway); err == nil {
		t.Fatal("gateway outside the network should be rejected")
	}
	invalidDNS := valid
	invalidDNS.DNSServers = []string{"not-an-address"}
	if err := validateNetworkInput(invalidDNS); err == nil {
		t.Fatal("invalid DNS address should be rejected")
	}
	invalidRange := valid
	invalidRange.RangeEnd = "10.201.1.10"
	if err := validateNetworkInput(invalidRange); err == nil {
		t.Fatal("IP range outside the network should be rejected")
	}
}

func TestNetworkRangeAddressesExcludesGateway(t *testing.T) {
	in := networkInput{CIDR: "10.200.8.0/22", Gateway: "10.200.9.131", RangeStart: "10.200.9.130", RangeEnd: "10.200.9.132"}
	addresses, err := networkRangeAddresses(in)
	if err != nil {
		t.Fatalf("valid IP range was rejected: %v", err)
	}
	if len(addresses) != 2 || addresses[0] != "10.200.9.130" || addresses[1] != "10.200.9.132" {
		t.Fatalf("gateway should be excluded, got %#v", addresses)
	}
}
