// Package packaging validates the Debian sandbox package and service contract.
// It does not itself install files, invoke a package manager, or call systemd.
package packaging

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Beowxlf/northgate-rmm/agent/internal/strictjson"
)

const maxDraftBytes = 16 * 1024

var (
	//go:embed debian/lifecycle.json
	lifecycleDraft []byte
	//go:embed debian/northgate-rmm-agent.service
	serviceDraft []byte
)

type lifecycleContract struct {
	SchemaVersion int       `json:"schema_version"`
	Status        string    `json:"status"`
	Target        target    `json:"target"`
	Paths         paths     `json:"paths"`
	Ownership     ownership `json:"ownership"`
	Lifecycle     lifecycle `json:"lifecycle"`
}

type target struct {
	Distribution string `json:"distribution"`
	Release      string `json:"release"`
	Architecture string `json:"architecture"`
}

type paths struct {
	Executable        string `json:"executable"`
	Unit              string `json:"unit"`
	Config            string `json:"config"`
	State             string `json:"state"`
	Identity          string `json:"identity"`
	RevocationReceipt string `json:"revocation_receipt"`
}

type ownership struct {
	Executable        string `json:"executable"`
	Unit              string `json:"unit"`
	ConfigDirectory   string `json:"config_directory"`
	Config            string `json:"config"`
	State             string `json:"state"`
	IdentityDirectory string `json:"identity_directory"`
	IdentityBundle    string `json:"identity_bundle"`
	RevocationReceipt string `json:"revocation_receipt"`
}

type lifecycle struct {
	Install   []string `json:"install"`
	Upgrade   []string `json:"upgrade"`
	Revoke    []string `json:"revoke"`
	Uninstall []string `json:"uninstall"`
	Purge     []string `json:"purge"`
}

var expectedActions = lifecycle{
	Install: []string{
		"create_locked_system_identity",
		"create_root_owned_config_directory",
		"create_private_state_directory",
		"install_root_owned_executable",
		"install_root_owned_unit",
		"daemon_reload",
		"leave_service_disabled",
	},
	Upgrade: []string{
		"stop_if_running",
		"replace_verified_executable",
		"replace_verified_unit",
		"daemon_reload",
		"preserve_config",
		"preserve_state",
		"preserve_identity",
		"preserve_enablement",
		"restart_only_if_previously_running",
		"restart_previous_if_upgrade_aborts",
	},
	Revoke: []string{
		"revoke_control_plane_identity",
		"stop_service",
		"disable_service",
		"remove_local_identity",
		"record_root_revocation_receipt",
	},
	Uninstall: []string{
		"require_root_revocation_receipt",
		"stop_service",
		"disable_service",
		"remove_unit",
		"remove_executable",
		"daemon_reload",
		"preserve_config",
		"preserve_state",
	},
	Purge: []string{
		"require_explicit_approval",
		"require_root_revocation_receipt",
		"require_evidence_export",
		"remove_state",
		"remove_system_identity",
		"remove_config",
	},
}

// ValidateDraft checks the embedded, non-installing Debian 12 amd64 package
// contract and hardened systemd unit for security-relevant drift.
func ValidateDraft() error {
	contract, err := decodeContract(lifecycleDraft)
	if err != nil {
		return err
	}
	if err := validateContract(contract); err != nil {
		return err
	}
	return validateUnit(serviceDraft)
}

func decodeContract(raw []byte) (lifecycleContract, error) {
	if len(raw) == 0 || len(raw) > maxDraftBytes {
		return lifecycleContract{}, errors.New("lifecycle draft is outside the size limit")
	}
	if err := strictjson.Validate(raw); err != nil {
		return lifecycleContract{}, fmt.Errorf("validate lifecycle JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var contract lifecycleContract
	if err := decoder.Decode(&contract); err != nil {
		return lifecycleContract{}, fmt.Errorf("decode lifecycle JSON: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return lifecycleContract{}, fmt.Errorf("decode trailing lifecycle data: %w", err)
		}
		return lifecycleContract{}, fmt.Errorf("unexpected trailing lifecycle token %v", token)
	}
	return contract, nil
}

func validateContract(contract lifecycleContract) error {
	if contract.SchemaVersion != 1 || contract.Status != "sandbox-package-test-only" ||
		contract.Target != (target{Distribution: "debian", Release: "12", Architecture: "amd64"}) {
		return errors.New("lifecycle metadata is outside the approved source draft")
	}
	wantPaths := paths{
		Executable:        "/usr/libexec/northgate-rmm/northgate-rmm-agent",
		Unit:              "/usr/lib/systemd/system/northgate-rmm-agent.service",
		Config:            "/etc/northgate-rmm/agent.json",
		State:             "/var/lib/northgate-rmm",
		Identity:          "/var/lib/northgate-rmm/identity",
		RevocationReceipt: "/etc/northgate-rmm/.identity-revoked",
	}
	if contract.Paths != wantPaths {
		return errors.New("lifecycle paths differ from the reviewed filesystem contract")
	}
	wantOwnership := ownership{
		Executable: "root:root:0755", Unit: "root:root:0644",
		ConfigDirectory: "root:root:0755", Config: "root:northgate-rmm:0640",
		State:             "northgate-rmm:northgate-rmm:0700",
		IdentityDirectory: "northgate-rmm:northgate-rmm:0700",
		IdentityBundle:    "northgate-rmm:northgate-rmm:0600",
		RevocationReceipt: "root:root:0600",
	}
	if contract.Ownership != wantOwnership {
		return errors.New("lifecycle ownership or modes differ from the reviewed contract")
	}
	for phase, actions := range map[string][]string{
		"install": contract.Lifecycle.Install, "upgrade": contract.Lifecycle.Upgrade,
		"revoke": contract.Lifecycle.Revoke, "uninstall": contract.Lifecycle.Uninstall,
		"purge": contract.Lifecycle.Purge,
	} {
		var expected []string
		switch phase {
		case "install":
			expected = expectedActions.Install
		case "upgrade":
			expected = expectedActions.Upgrade
		case "revoke":
			expected = expectedActions.Revoke
		case "uninstall":
			expected = expectedActions.Uninstall
		case "purge":
			expected = expectedActions.Purge
		}
		if !equalStrings(actions, expected) {
			return fmt.Errorf("%s lifecycle differs from the reviewed order", phase)
		}
	}
	return nil
}

func validateUnit(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxDraftBytes {
		return errors.New("systemd draft is outside the size limit")
	}
	sections := make(map[string]map[string]string)
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 256), maxDraftBytes)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if section == "" {
				return errors.New("systemd draft contains an empty section")
			}
			if _, exists := sections[section]; exists {
				return errors.New("systemd draft contains a duplicate section")
			}
			sections[section] = make(map[string]string)
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || section == "" || key == "" || strings.TrimSpace(key) != key ||
			strings.TrimSpace(value) != value || strings.ContainsAny(line, "\r\x00") {
			return errors.New("systemd draft contains a malformed directive")
		}
		if _, exists := sections[section][key]; exists {
			return fmt.Errorf("systemd draft contains duplicate directive %s.%s", section, key)
		}
		sections[section][key] = value
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan systemd draft: %w", err)
	}

	required := map[string]map[string]string{
		"Unit": {
			"Description":           "NorthGate RMM read-only agent (G2 closed)",
			"After":                 "network-online.target",
			"Wants":                 "network-online.target",
			"StartLimitIntervalSec": "300",
			"StartLimitBurst":       "5",
		},
		"Service": {
			"Type": "exec", "User": "northgate-rmm", "Group": "northgate-rmm",
			"ExecStart":        "/usr/libexec/northgate-rmm/northgate-rmm-agent --config /etc/northgate-rmm/agent.json",
			"WorkingDirectory": "/var/lib/northgate-rmm", "Restart": "on-failure", "RestartSec": "30s",
			"TimeoutStopSec": "30s", "UMask": "0077", "NoNewPrivileges": "true",
			"PrivateTmp": "true", "PrivateDevices": "true", "ProtectSystem": "strict",
			"ProtectHome": "true", "ProtectKernelTunables": "true", "ProtectKernelModules": "true",
			"ProtectKernelLogs": "true", "ProtectControlGroups": "true", "ProtectProc": "invisible",
			"RestrictNamespaces": "true", "RestrictSUIDSGID": "true",
			"LockPersonality": "true", "MemoryDenyWriteExecute": "true", "RestrictRealtime": "true",
			"SystemCallArchitectures": "native", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
			"CapabilityBoundingSet": "", "AmbientCapabilities": "", "StateDirectory": "northgate-rmm",
			"StateDirectoryMode": "0700", "RuntimeDirectory": "northgate-rmm", "RuntimeDirectoryMode": "0700",
			"ReadOnlyPaths": "/etc/northgate-rmm", "MemoryMax": "128M", "CPUQuota": "20%",
			"TasksMax": "64", "LimitNOFILE": "1024", "StandardOutput": "journal",
			"StandardError": "journal", "SyslogIdentifier": "northgate-rmm-agent",
		},
		"Install": {"WantedBy": "multi-user.target"},
	}
	if len(sections) != len(required) {
		return errors.New("systemd draft contains an unexpected section")
	}
	for name, directives := range required {
		actual, ok := sections[name]
		if !ok || len(actual) != len(directives) {
			return fmt.Errorf("systemd section %s differs from the reviewed schema", name)
		}
		for key, value := range directives {
			if actual[key] != value {
				return fmt.Errorf("systemd directive %s.%s differs from the reviewed value", name, key)
			}
		}
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
