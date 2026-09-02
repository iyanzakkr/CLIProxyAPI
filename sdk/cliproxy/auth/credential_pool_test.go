package auth

import (
	"context"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestResolveCredentialPoolForAPIKeyDefaults(t *testing.T) {
	cfg := &internalconfig.Config{
		CredentialPools: map[string]internalconfig.CredentialPool{
			"default": {
				Claude: []string{"claude-1", "claude-2", "claude-3"},
				Codex:  []string{"codex-1", "codex-2", "codex-3"},
			},
			"extended": {
				Claude: []string{"claude-1", "claude-2", "claude-3", "claude-4", "claude-5"},
				Codex:  []string{"codex-1", "codex-2", "codex-3", "codex-4", "codex-5"},
			},
		},
		APIKeyPools: map[string]string{
			"sk-paperclip": "extended",
			"*":            "default",
		},
	}

	paperclip := ResolveCredentialPoolForAPIKey(cfg, "sk-paperclip")
	if paperclip == nil || paperclip.Name != "extended" {
		t.Fatalf("expected paperclip key to resolve to extended pool, got %+v", paperclip)
	}

	normal := ResolveCredentialPoolForAPIKey(cfg, "sk-some-other-key")
	if normal == nil || normal.Name != "default" {
		t.Fatalf("expected unmatched key to fall back to default pool, got %+v", normal)
	}

	unrestricted := ResolveCredentialPoolForAPIKey(&internalconfig.Config{}, "sk-anything")
	if unrestricted != nil {
		t.Fatalf("expected no pools configured to mean unrestricted, got %+v", unrestricted)
	}
}

func TestResolveCredentialPoolForAPIKeyUnknownPoolFailsClosed(t *testing.T) {
	cfg := &internalconfig.Config{
		APIKeyPools: map[string]string{
			"sk-broken": "does-not-exist",
		},
	}
	pool := ResolveCredentialPoolForAPIKey(cfg, "sk-broken")
	if pool == nil {
		t.Fatalf("expected a resolved (but empty) pool for an unknown pool name, got nil")
	}
	claudeAuth := &Auth{Provider: "claude", FileName: "claude-1.json"}
	if pool.Allows(claudeAuth) {
		t.Fatalf("expected an unknown pool to deny every credential, but claude-1 was allowed")
	}
}

func TestResolvedCredentialPoolAllowsMatchesByFileLabelOrID(t *testing.T) {
	pool := &ResolvedCredentialPool{
		Name:   "default",
		Claude: []string{"claude-account-1", "Ops Claude 2"},
		Codex:  []string{"codex-account-1"},
	}

	cases := []struct {
		name string
		auth *Auth
		want bool
	}{
		{"claude allowed by file name with extension", &Auth{Provider: "claude", FileName: "/root/.cli-proxy-api/claude-account-1.json"}, true},
		{"claude allowed by file name without extension", &Auth{Provider: "claude", FileName: "claude-account-1"}, true},
		{"claude allowed by label case-insensitive", &Auth{Provider: "claude", Label: "ops claude 2"}, true},
		{"claude denied when not listed", &Auth{Provider: "claude", FileName: "claude-account-9.json"}, false},
		{"codex allowed by file name", &Auth{Provider: "codex", FileName: "codex-account-1.json"}, true},
		{"codex denied when not listed", &Auth{Provider: "codex", FileName: "codex-account-9.json"}, false},
		{"gemini is never restricted", &Auth{Provider: "gemini", FileName: "anything.json"}, true},
		{"xai is never restricted", &Auth{Provider: "xai", FileName: "anything.json"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pool.Allows(tc.auth); got != tc.want {
				t.Fatalf("Allows() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolvedCredentialPoolNilAllowsEverything(t *testing.T) {
	var pool *ResolvedCredentialPool
	if !pool.Allows(&Auth{Provider: "claude", FileName: "claude-1.json"}) {
		t.Fatalf("expected a nil pool to allow every credential")
	}
	if pool.Allows(nil) {
		t.Fatalf("expected a nil auth to never be allowed")
	}
}

func TestCredentialPoolAllowsAppliesThroughEligibility(t *testing.T) {
	pool := &ResolvedCredentialPool{
		Name:   "default",
		Claude: []string{"claude-1"},
		Codex:  []string{"codex-1"},
	}
	ctx := WithCredentialPool(context.Background(), pool)

	eligibility := authSelectionEligibilityForRequest(ctx, cliproxyexecutor.Options{})
	allowed := &Auth{Provider: "claude", FileName: "claude-1.json"}
	denied := &Auth{Provider: "claude", FileName: "claude-2.json"}
	gemini := &Auth{Provider: "gemini", FileName: "anything.json"}

	if !eligibility.allows(allowed) {
		t.Fatalf("expected claude-1 to be allowed for the default pool")
	}
	if eligibility.allows(denied) {
		t.Fatalf("expected claude-2 to be denied for the default pool")
	}
	if !eligibility.allows(gemini) {
		t.Fatalf("expected gemini to remain unrestricted regardless of pool")
	}
}
