package config

import (
	"reflect"
	"testing"
)

func TestResolveCredentialPoolUnconfiguredIsUnrestricted(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
	}{
		{name: "nil config", cfg: nil},
		{name: "zero value config", cfg: &Config{}},
		{name: "pools without key mapping", cfg: &Config{
			CredentialPools: map[string]map[string][]string{
				"default": {"claude": {"claude-account-1"}},
			},
		}},
		{name: "key mapping without pools", cfg: &Config{
			APIKeyPools: map[string]string{"*": "default"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allowed, ok := test.cfg.ResolveCredentialPool("any-key", "claude")
			if ok {
				t.Fatalf("ResolveCredentialPool() ok = true, allowed = %v, want unrestricted (ok=false)", allowed)
			}
		})
	}
}

func credentialPoolTestConfig() *Config {
	return &Config{
		CredentialPools: map[string]map[string][]string{
			"default": {
				"claude": {"claude-account-1", "claude-account-2", "claude-account-3"},
				"codex":  {"codex-account-1", "codex-account-2", "codex-account-3"},
			},
			"extended": {
				"claude": {"claude-account-1", "claude-account-2", "claude-account-3", "claude-account-4", "claude-account-5"},
				"codex":  {"codex-account-1", "codex-account-2", "codex-account-3", "codex-account-4", "codex-account-5"},
			},
		},
		APIKeyPools: map[string]string{
			"paperclip": "extended",
			"*":         "default",
		},
	}
}

func TestResolveCredentialPoolDefaultKeyIsRestrictedToDefaultPool(t *testing.T) {
	cfg := credentialPoolTestConfig()

	allowed, ok := cfg.ResolveCredentialPool("some-ordinary-key", "claude")
	if !ok {
		t.Fatal("ResolveCredentialPool() ok = false, want restricted via the \"*\" fallback pool")
	}
	want := []string{"claude-account-1", "claude-account-2", "claude-account-3"}
	if !reflect.DeepEqual(allowed, want) {
		t.Fatalf("ResolveCredentialPool() allowed = %v, want %v", allowed, want)
	}
}

func TestResolveCredentialPoolNamedKeyReachesWiderPool(t *testing.T) {
	cfg := credentialPoolTestConfig()

	allowed, ok := cfg.ResolveCredentialPool("paperclip", "codex")
	if !ok {
		t.Fatal("ResolveCredentialPool() ok = false, want restricted via the \"paperclip\" entry")
	}
	want := []string{"codex-account-1", "codex-account-2", "codex-account-3", "codex-account-4", "codex-account-5"}
	if !reflect.DeepEqual(allowed, want) {
		t.Fatalf("ResolveCredentialPool() allowed = %v, want %v", allowed, want)
	}
	for _, id := range want[3:] {
		found := false
		for _, defaultAllowed := range mustResolve(t, cfg, "some-ordinary-key", "codex") {
			if defaultAllowed == id {
				found = true
			}
		}
		if found {
			t.Fatalf("credential %q leaked into the default pool", id)
		}
	}
}

func mustResolve(t *testing.T, cfg *Config, apiKey, provider string) []string {
	t.Helper()
	allowed, ok := cfg.ResolveCredentialPool(apiKey, provider)
	if !ok {
		t.Fatalf("ResolveCredentialPool(%q, %q) ok = false", apiKey, provider)
	}
	return allowed
}

func TestResolveCredentialPoolProviderAbsentFromPoolIsUnrestricted(t *testing.T) {
	cfg := credentialPoolTestConfig()

	// "gemini" is never listed inside either pool, so it must stay unrestricted for
	// every API key -- this is how the shared Gemini pool requirement is satisfied.
	if _, ok := cfg.ResolveCredentialPool("paperclip", "gemini"); ok {
		t.Fatal("ResolveCredentialPool() ok = true for a provider absent from every pool, want unrestricted")
	}
	if _, ok := cfg.ResolveCredentialPool("some-ordinary-key", "GEMINI"); ok {
		t.Fatal("ResolveCredentialPool() ok = true for a provider absent from every pool (case-insensitive), want unrestricted")
	}
}

func TestResolveCredentialPoolProviderMatchIsCaseInsensitive(t *testing.T) {
	cfg := credentialPoolTestConfig()

	allowed, ok := cfg.ResolveCredentialPool("some-ordinary-key", "Claude")
	if !ok {
		t.Fatal("ResolveCredentialPool() ok = false, want case-insensitive provider match")
	}
	if len(allowed) != 3 {
		t.Fatalf("ResolveCredentialPool() allowed = %v, want 3 entries", allowed)
	}
}

func TestResolveCredentialPoolUnknownPoolNameIsUnrestricted(t *testing.T) {
	cfg := &Config{
		CredentialPools: map[string]map[string][]string{
			"default": {"claude": {"claude-account-1"}},
		},
		APIKeyPools: map[string]string{"*": "does-not-exist"},
	}
	if _, ok := cfg.ResolveCredentialPool("any-key", "claude"); ok {
		t.Fatal("ResolveCredentialPool() ok = true for an undefined pool name, want unrestricted")
	}
}

func TestNormalizeCredentialPools(t *testing.T) {
	in := map[string]map[string][]string{
		" default ": {
			" Claude ": {" claude-account-1 ", "claude-account-1", "", "claude-account-2"},
			"":         {"dropped-because-empty-provider"},
			"codex":    {"  "},
		},
		"": {"claude": {"dropped-because-empty-pool-name"}},
	}
	out := NormalizeCredentialPools(in)
	want := map[string]map[string][]string{
		"default": {
			"claude": {"claude-account-1", "claude-account-2"},
		},
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("NormalizeCredentialPools() = %#v, want %#v", out, want)
	}
	if NormalizeCredentialPools(nil) != nil {
		t.Fatal("NormalizeCredentialPools(nil) != nil")
	}
}

func TestNormalizeAPIKeyPools(t *testing.T) {
	in := map[string]string{
		" paperclip ": " extended ",
		"*":           "default",
		"":            "dropped-because-empty-key",
		"empty-pool":  "  ",
	}
	out := NormalizeAPIKeyPools(in)
	want := map[string]string{
		"paperclip": "extended",
		"*":         "default",
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("NormalizeAPIKeyPools() = %#v, want %#v", out, want)
	}
	if NormalizeAPIKeyPools(nil) != nil {
		t.Fatal("NormalizeAPIKeyPools(nil) != nil")
	}
}
