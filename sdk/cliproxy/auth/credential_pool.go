package auth

import (
	"context"
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// ResolvedCredentialPool carries the concrete Claude/Codex credential allow-lists for
// one downstream request. It is resolved once, from Config.CredentialPools and
// Config.APIKeyPools, at the HTTP boundary (see internal/api's credentialPoolMiddleware)
// and then carried unchanged through the request context into every auth-selection
// call: the initial candidate list, every retry round, cooldown-wait computation, and
// session affinity all read the same resolution via authSelectionEligibility.allows.
// Nothing re-reads config after the initial resolution, which is what guarantees a
// restricted downstream key can never reach a credential outside its pool through any
// code path (retry/failover included).
type ResolvedCredentialPool struct {
	// Name is the resolved pool name, kept only for logs/diagnostics.
	Name string
	// Claude lists the allowed Claude credential identifiers for this pool.
	Claude []string
	// Codex lists the allowed Codex credential identifiers for this pool.
	Codex []string
}

type credentialPoolContextKey struct{}

// WithCredentialPool attaches a resolved credential pool to ctx. It is exported so the
// HTTP layer (internal/api) can attach the pool resolved for the authenticated
// downstream API key before calling into auth selection. Passing a nil pool leaves ctx
// unchanged, meaning "no restriction" (legacy, pre-pools behavior).
func WithCredentialPool(ctx context.Context, pool *ResolvedCredentialPool) context.Context {
	if pool == nil {
		return ctx
	}
	return context.WithValue(ctx, credentialPoolContextKey{}, pool)
}

// credentialPoolFromContext returns the pool attached by WithCredentialPool, if any.
func credentialPoolFromContext(ctx context.Context) *ResolvedCredentialPool {
	if ctx == nil {
		return nil
	}
	pool, _ := ctx.Value(credentialPoolContextKey{}).(*ResolvedCredentialPool)
	return pool
}

// ResolveCredentialPoolForAPIKey resolves the credential pool that should restrict a
// downstream API key's Claude/Codex auth selection, honoring the "*" default pool
// entry in Config.APIKeyPools. It returns nil when no pool restriction applies to the
// key - either no pools are configured at all, or the key has no specific entry and no
// "*" default is set - which preserves legacy, unrestricted-selection behavior.
//
// A configured pool name with no matching Config.CredentialPools entry fails closed:
// it returns an empty ResolvedCredentialPool (denying every Claude/Codex credential)
// rather than silently running unrestricted, since running unrestricted would defeat
// the point of assigning that key to a pool.
func ResolveCredentialPoolForAPIKey(cfg *internalconfig.Config, apiKey string) *ResolvedCredentialPool {
	if cfg == nil || len(cfg.APIKeyPools) == 0 {
		return nil
	}
	apiKey = strings.TrimSpace(apiKey)
	poolName := ""
	if apiKey != "" {
		if name, ok := cfg.APIKeyPools[apiKey]; ok {
			poolName = strings.TrimSpace(name)
		}
	}
	if poolName == "" {
		if name, ok := cfg.APIKeyPools["*"]; ok {
			poolName = strings.TrimSpace(name)
		}
	}
	if poolName == "" {
		return nil
	}
	entry, ok := cfg.CredentialPools[poolName]
	if !ok {
		return &ResolvedCredentialPool{Name: poolName}
	}
	return &ResolvedCredentialPool{Name: poolName, Claude: entry.Claude, Codex: entry.Codex}
}

// Allows reports whether auth belongs to this pool for its own provider. Only
// "claude" and "codex" credentials are ever restricted; every other provider -
// Gemini included - is always allowed, so its capacity stays shared across all
// downstream keys regardless of pool configuration.
func (p *ResolvedCredentialPool) Allows(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if p == nil {
		return true
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	var allowed []string
	switch provider {
	case "claude":
		allowed = p.Claude
	case "codex":
		allowed = p.Codex
	default:
		// Gemini and every other provider are never restricted by credential pools.
		return true
	}
	if len(allowed) == 0 {
		// A pool that does not list any credential for this provider denies every
		// credential for it (fail closed) instead of silently granting unrestricted
		// access to a provider the pool never mentions.
		return false
	}
	return credentialMatchesAny(auth, allowed)
}

// credentialMatchesAny reports whether auth is identified by any of the configured
// pool entries. Entries may reference a credential by its auth file name (with or
// without the .json extension), its configured label, or its stable auth ID, so
// operators can copy whichever identifier the Credential Management UI shows them.
func credentialMatchesAny(auth *Auth, entries []string) bool {
	fileBase := credentialFileBase(auth.FileName)
	label := strings.TrimSpace(auth.Label)
	id := strings.TrimSpace(auth.ID)
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if fileBase != "" && strings.EqualFold(entry, fileBase) {
			return true
		}
		if label != "" && strings.EqualFold(entry, label) {
			return true
		}
		if id != "" && strings.EqualFold(entry, id) {
			return true
		}
	}
	return false
}

// credentialFileBase returns the base file name of an auth file with its directory
// and .json extension stripped (e.g. "/root/.cli-proxy-api/claude-1.json" -> "claude-1").
func credentialFileBase(fileName string) string {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return ""
	}
	base := fileName
	if idx := strings.LastIndexAny(base, `/\`); idx >= 0 {
		base = base[idx+1:]
	}
	return strings.TrimSuffix(base, ".json")
}
