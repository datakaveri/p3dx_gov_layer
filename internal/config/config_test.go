package config

import (
	"testing"
	"time"
)

func TestFLContractValidity(t *testing.T) {
	cases := map[string]time.Duration{
		"":         DefaultFLContractValidity,
		"720h":     720 * time.Hour,
		"30m":      30 * time.Minute,
		"0s":       DefaultFLContractValidity,
		"-5h":      DefaultFLContractValidity,
		"ninety":   DefaultFLContractValidity,
		" 2160h  ": 2160 * time.Hour,
	}
	for in, want := range cases {
		t.Setenv("FL_CONTRACT_VALIDITY", in)
		if got := Load().FLContractValidity; got != want {
			t.Errorf("FL_CONTRACT_VALIDITY=%q: got %s, want %s", in, got, want)
		}
	}
	if DefaultFLContractValidity != 2160*time.Hour {
		t.Fatalf("default validity = %s, want 2160h", DefaultFLContractValidity)
	}
}

func TestGatewayDefaults(t *testing.T) {
	for _, k := range []string{"GOV_CA_CERT_PATH", "ORCHESTRATOR_CLIENT_ID", "ORCHESTRATOR_ROLE", "FLOTILLA_VM_CLIENT_ID"} {
		t.Setenv(k, "")
	}
	c := Load()
	if c.GovCACertPath != "./keys/governance_ca.pem" || c.OrchestratorClientID != "p3dx-fl-orchestrator" ||
		c.OrchestratorRole != "fl-orchestrator" || c.FlotillaVMClientID != "flotilla-vm" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}
