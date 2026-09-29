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
