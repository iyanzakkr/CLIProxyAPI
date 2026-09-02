package config

import "strings"

// NormalizeCredentialPools lowercases and trims pool names, provider keys, and
// credential IDs in CredentialPools, mirroring the normalization applied to other
// provider-keyed maps (see NormalizeOAuthExcludedModels). Empty pools, providers,
// or credential ID lists are dropped. A nil or empty input returns nil.
func NormalizeCredentialPools(pools map[string]map[string][]string) map[string]map[string][]string {
	if len(pools) == 0 {
		return nil
	}
	out := make(map[string]map[string][]string, len(pools))
	for poolName, providers := range pools {
		name := strings.TrimSpace(poolName)
		if name == "" || len(providers) == 0 {
			continue
		}
		normalizedProviders := make(map[string][]string, len(providers))
		for provider, ids := range providers {
			providerKey := strings.ToLower(strings.TrimSpace(provider))
			if providerKey == "" {
				continue
			}
			normalizedIDs := normalizeCredentialPoolIDs(ids)
			if len(normalizedIDs) == 0 {
				continue
			}
			normalizedProviders[providerKey] = normalizedIDs
		}
		if len(normalizedProviders) == 0 {
			continue
		}
		out[name] = normalizedProviders
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeCredentialPoolIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeAPIKeyPools trims API key principals and pool names in APIKeyPools. The
// wildcard key "*" is preserved verbatim as the fallback-pool marker. Entries with an
// empty key or empty pool name are dropped. A nil or empty input returns nil.
func NormalizeAPIKeyPools(pools map[string]string) map[string]string {
	if len(pools) == 0 {
		return nil
	}
	out := make(map[string]string, len(pools))
	for apiKey, poolName := range pools {
		key := strings.TrimSpace(apiKey)
		name := strings.TrimSpace(poolName)
		if key == "" || name == "" {
			continue
		}
		out[key] = name
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ResolveCredentialPool returns the upstream credential IDs a downstream API key is
// allowed to use for the given provider, based on CredentialPools/APIKeyPools.
//
// ok=false means "no restriction configured for this key+provider" -- callers MUST
// treat this as unrestricted (identical to today's behavior), never as "deny all".
// This is the case whenever:
//   - CredentialPools or APIKeyPools is empty (the default: this feature is strictly
//     opt-in and never filters an unconfigured deployment);
//   - apiKeyPrincipal has neither an exact entry in APIKeyPools nor a "*" fallback;
//   - the pool name the API key resolves to is not defined in CredentialPools; or
//   - provider is not listed inside that pool (e.g. a deployment that only lists
//     "claude" and "codex" inside its pools leaves "gemini" fully shared/unfiltered).
//
// ok=true with a non-empty allowed slice means the caller must drop any candidate
// whose Auth.ID is not in allowed. ok=true with an empty allowed slice is a valid,
// if unusual, configuration that explicitly restricts the provider to zero
// credentials for this key (callers see "no eligible credential" for that provider).
//
// provider is matched case-insensitively; apiKeyPrincipal is matched exactly (after
// trimming), since API keys are opaque tokens rather than display names.
func (c *Config) ResolveCredentialPool(apiKeyPrincipal, provider string) (allowed []string, ok bool) {
	if c == nil || len(c.CredentialPools) == 0 || len(c.APIKeyPools) == 0 {
		return nil, false
	}
	providerKey := strings.ToLower(strings.TrimSpace(provider))
	if providerKey == "" {
		return nil, false
	}

	poolName, matched := c.APIKeyPools[strings.TrimSpace(apiKeyPrincipal)]
	if !matched {
		poolName, matched = c.APIKeyPools["*"]
	}
	if !matched {
		return nil, false
	}

	pool, poolExists := c.CredentialPools[poolName]
	if !poolExists {
		return nil, false
	}

	ids, providerExists := pool[providerKey]
	if !providerExists {
		return nil, false
	}
	return ids, true
}
