package auth

import (
	"context"
	"reflect"
	"sort"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// credentialPoolTestConfig mirrors the credential-pools example: "default" (accounts
// 1-3) is the fallback pool for every API key via "*"; "extended" (accounts 1-5) is
// reserved for the "paperclip" key. Only "claude" is listed in either pool, so any
// other provider (e.g. "gemini") stays completely unrestricted.
func credentialPoolTestConfig() *internalconfig.Config {
	return &internalconfig.Config{
		CredentialPools: map[string]map[string][]string{
			"default": {
				"claude": {"claude-account-1", "claude-account-2", "claude-account-3"},
			},
			"extended": {
				"claude": {"claude-account-1", "claude-account-2", "claude-account-3", "claude-account-4", "claude-account-5"},
			},
		},
		APIKeyPools: map[string]string{
			"paperclip": "extended",
			"*":         "default",
		},
	}
}

// runCredentialPoolExecute drives a Manager through the same failing-executor retry
// sweep used by TestExecuteRetryRoundCredentialWindows: every registered credential
// eventually gets tried (the executor always fails), so the returned ID set is exactly
// every credential the scheduler considered eligible for opts across the whole retry
// sweep -- including any additional retry rounds. This is what exercises "never
// returned even after a simulated retry/re-pick" for scenario (e).
func runCredentialPoolExecute(t *testing.T, cfg *internalconfig.Config, provider string, ids []string, opts cliproxyexecutor.Options) []string {
	t.Helper()
	manager := NewManager(nil, nil, nil)
	if cfg != nil {
		manager.SetConfig(cfg)
	}
	manager.SetRetryConfig(3, 0, 0)
	executor := &retryRoundCallExecutor{identifier: provider}
	manager.RegisterExecutor(executor)

	limits := make(map[string]int, len(ids))
	for _, id := range ids {
		limits[id] = 3
	}
	registerRetryRoundLocalAuths(t, manager, provider, "credential-pool-model", limits)

	if _, errExecute := manager.Execute(context.Background(), []string{provider}, cliproxyexecutor.Request{Model: "credential-pool-model"}, opts); errExecute == nil {
		t.Fatal("execution error = nil, want terminal failure (executor always fails)")
	}
	seen := map[string]struct{}{}
	for _, id := range executor.ids("execute") {
		seen[id] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func optsWithAPIKeyPrincipal(principal string) cliproxyexecutor.Options {
	if principal == "" {
		return cliproxyexecutor.Options{}
	}
	return cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.APIKeyPrincipalMetadataKey: principal,
	}}
}

// Every claude-provider subtest below MUST use the literal provider key "claude" --
// ResolveCredentialPool matches Auth.Provider against the CredentialPools provider key
// exactly (case-insensitively), and credentialPoolTestConfig only lists pools under
// "claude". Manager.Execute's providers argument is only the *executor* routing key
// (m.executors["claude"]); it is independent of Auth.Provider, so every subtest can
// safely register its own "claude" executor without colliding with the others --
// each test gets its own fresh Manager and RegisterExecutor call.

// (a) No pools configured anywhere -- regression safety: selection stays fully
// unfiltered, identical to today's behavior.
func TestCredentialPoolsUnconfiguredSelectionIsUnfiltered(t *testing.T) {
	allAccounts := []string{"claude-account-1", "claude-account-2", "claude-account-3", "claude-account-4", "claude-account-5"}
	got := runCredentialPoolExecute(t, nil, "claude", allAccounts, cliproxyexecutor.Options{})
	if !reflect.DeepEqual(got, allAccounts) {
		t.Fatalf("credentials reached = %v, want every registered credential reached: %v", got, allAccounts)
	}
}

// (b) A default (unmapped) API key is restricted to the "default" pool.
func TestCredentialPoolsDefaultKeyIsRestrictedToDefaultPool(t *testing.T) {
	allAccounts := []string{"claude-account-1", "claude-account-2", "claude-account-3", "claude-account-4", "claude-account-5"}
	got := runCredentialPoolExecute(t, credentialPoolTestConfig(), "claude", allAccounts, optsWithAPIKeyPrincipal("some-ordinary-key"))
	want := []string{"claude-account-1", "claude-account-2", "claude-account-3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credentials reached = %v, want exactly the default pool %v (accounts 4 and 5 must never appear)", got, want)
	}
}

// (c) The "paperclip" key reaches the wider "extended" pool, including credentials the
// default pool excludes.
func TestCredentialPoolsNamedKeyReachesWiderPool(t *testing.T) {
	allAccounts := []string{"claude-account-1", "claude-account-2", "claude-account-3", "claude-account-4", "claude-account-5"}
	got := runCredentialPoolExecute(t, credentialPoolTestConfig(), "claude", allAccounts, optsWithAPIKeyPrincipal("paperclip"))
	if !reflect.DeepEqual(got, allAccounts) {
		t.Fatalf("credentials reached = %v, want all five extended-pool credentials reached: %v", got, allAccounts)
	}
}

// (d) A provider absent from every pool (gemini in the example) is never filtered,
// even though pools are configured for other providers.
func TestCredentialPoolsProviderAbsentFromPoolsIsUnfiltered(t *testing.T) {
	geminiAccounts := []string{"gemini-account-1", "gemini-account-2"}
	got := runCredentialPoolExecute(t, credentialPoolTestConfig(), "gemini", geminiAccounts, optsWithAPIKeyPrincipal("some-ordinary-key"))
	if !reflect.DeepEqual(got, geminiAccounts) {
		t.Fatalf("credentials reached = %v, want both shared Gemini credentials reached: %v", got, geminiAccounts)
	}
}

// (e) A credential outside the resolved pool is never returned even after the retry
// sweep exhausts every other eligible credential. runCredentialPoolExecute already
// drives Manager.Execute through its full failing-credential retry loop (the same
// mechanism TestExecuteRetryRoundCredentialWindows exercises), so this reuses (b) and
// (c) above as the retry-safety assertion: if pool filtering only applied to the first
// pick and not to retries, account-4/account-5 would leak into the default-key result
// once accounts 1-3 are exhausted. They must not.
func TestCredentialPoolsNeverLeakAcrossRetryRounds(t *testing.T) {
	allAccounts := []string{"claude-account-1", "claude-account-2", "claude-account-3", "claude-account-4", "claude-account-5"}
	got := runCredentialPoolExecute(t, credentialPoolTestConfig(), "claude", allAccounts, optsWithAPIKeyPrincipal("some-ordinary-key"))
	forbidden := map[string]bool{"claude-account-4": true, "claude-account-5": true}
	for _, id := range got {
		if forbidden[id] {
			t.Fatalf("credential %q was reached during the retry sweep, want it excluded from the default pool for every attempt", id)
		}
	}
	want := []string{"claude-account-1", "claude-account-2", "claude-account-3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credentials reached = %v, want exactly %v", got, want)
	}
}
