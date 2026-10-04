package platform

import (
	"encoding/json"
	"testing"
)

func TestDecodeCreateApprovalPayloadUsesApprovedHours(t *testing.T) {
	payload, err := json.Marshal(CreateApplicationInput{
		InstanceName: "approval-hours-test",
		Purpose:      "验证审批调整租期",
		FlavorID:     "flavor-id",
		ImageID:      "image-id",
		NetworkID:    "network-id",
		LeaseHours:   336,
	})
	if err != nil {
		t.Fatal(err)
	}

	input, err := decodeCreateApprovalPayload(payload, 168)
	if err != nil {
		t.Fatal(err)
	}
	if input.LeaseHours != 168 {
		t.Fatalf("创建执行租期 = %d，期望 168", input.LeaseHours)
	}
}
