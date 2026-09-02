package packaging

import (
	"bytes"
	"strings"
	"testing"
)

func TestEmbeddedDraftPassesReviewContract(t *testing.T) {
	if err := ValidateDraft(); err != nil {
		t.Fatalf("ValidateDraft() error = %v", err)
	}
}

func TestLifecycleRejectsUnknownOrReorderedActions(t *testing.T) {
	for _, raw := range [][]byte{
		bytes.Replace(lifecycleDraft, []byte(`"leave_service_disabled"`), []byte(`"enable_service"`), 1),
		bytes.Replace(lifecycleDraft, []byte("\"require_identity_revoked\",\n      \"stop_service\""), []byte("\"stop_service\",\n      \"require_identity_revoked\""), 1),
		bytes.Replace(lifecycleDraft, []byte(`"status": "sandbox-package-test-only"`), []byte(`"status": "endpoint-installable"`), 1),
		append(append([]byte{}, lifecycleDraft...), []byte(` {}`)...),
	} {
		contract, err := decodeContract(raw)
		if err == nil {
			err = validateContract(contract)
		}
		if err == nil {
			t.Fatal("modified lifecycle contract was accepted")
		}
	}
}

func TestUnitRejectsRootShellAndWeakenedLimits(t *testing.T) {
	for _, replacement := range []struct{ old, new string }{
		{"User=northgate-rmm", "User=root"},
		{"ExecStart=/usr/libexec/northgate-rmm/northgate-rmm-agent --config /etc/northgate-rmm/agent.json", "ExecStart=/bin/sh -c agent"},
		{"NoNewPrivileges=true", "NoNewPrivileges=false"},
		{"MemoryMax=128M", "MemoryMax=infinity"},
		{"CapabilityBoundingSet=", "CapabilityBoundingSet=CAP_SYS_ADMIN"},
	} {
		modified := strings.Replace(string(serviceDraft), replacement.old, replacement.new, 1)
		if err := validateUnit([]byte(modified)); err == nil {
			t.Fatalf("systemd weakening %q was accepted", replacement.new)
		}
	}
}

func TestUnitRejectsAdditionalEnvironmentAndDirectives(t *testing.T) {
	modified := strings.Replace(string(serviceDraft), "User=northgate-rmm", "User=northgate-rmm\nEnvironment=TOKEN=value", 1)
	if err := validateUnit([]byte(modified)); err == nil {
		t.Fatal("unexpected environment directive was accepted")
	}
}

func TestUnitKeepsBootIdentityPathVisible(t *testing.T) {
	if bytes.Contains(serviceDraft, []byte("ProcSubset=pid")) {
		t.Fatal("systemd draft hides /proc/sys/kernel/random/boot_id")
	}
	modified := strings.Replace(string(serviceDraft), "ProtectProc=invisible", "ProtectProc=invisible\nProcSubset=pid", 1)
	if err := validateUnit([]byte(modified)); err == nil {
		t.Fatal("systemd draft accepted a hidden boot identity path")
	}
}

func TestHermeticLifecycleModelRequiresRevokeAndApproval(t *testing.T) {
	state := packageState{}
	state.install()
	if !state.binary || !state.unit || state.identity || state.enabled || state.running {
		t.Fatalf("install violated disabled-by-default policy: %#v", state)
	}
	state.enroll()
	state.upgrade()
	if !state.config || !state.state || !state.identity {
		t.Fatalf("upgrade did not preserve state: %#v", state)
	}
	if state.uninstall() {
		t.Fatal("uninstall succeeded before identity revocation")
	}
	state.revoke()
	if !state.uninstall() || state.binary || state.unit || !state.config || !state.state {
		t.Fatalf("uninstall outcome is invalid: %#v", state)
	}
	if state.purge(false, true) || state.purge(true, false) {
		t.Fatal("purge succeeded without approval and evidence")
	}
	if !state.purge(true, true) || state.config || state.state || state.systemIdentity {
		t.Fatalf("approved purge outcome is invalid: %#v", state)
	}
}

// packageState is a networkless, filesystemless lifecycle model used only to
// prove ordering and preservation rules in tests.
type packageState struct {
	systemIdentity  bool
	binary          bool
	unit            bool
	config          bool
	state           bool
	identity        bool
	identityRevoked bool
	enabled         bool
	running         bool
}

func (state *packageState) install() {
	state.systemIdentity = true
	state.binary = true
	state.unit = true
	state.config = true
	state.state = true
}

func (state *packageState) enroll() { state.identity = true }

func (state *packageState) upgrade() {
	state.binary = true
	state.unit = true
}

func (state *packageState) revoke() {
	state.identityRevoked = true
	state.identity = false
	state.enabled = false
	state.running = false
}

func (state *packageState) uninstall() bool {
	if !state.identityRevoked {
		return false
	}
	state.running = false
	state.enabled = false
	state.binary = false
	state.unit = false
	return true
}

func (state *packageState) purge(approved, evidenceExported bool) bool {
	if !approved || !evidenceExported || !state.identityRevoked {
		return false
	}
	state.config = false
	state.state = false
	state.systemIdentity = false
	return true
}
