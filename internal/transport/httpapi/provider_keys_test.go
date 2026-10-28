package httpapi

import "testing"

func TestHasProviderKeyRole(t *testing.T) {
	devRoles := []string{"provider", "offline_access", "default-roles-tgdex-pilot", "consumer"}
	cases := []struct {
		name         string
		roles        []string
		role, dpRole string
		want         bool
	}{
		{"dev provider token on data-provider", devRoles, "data-provider", "data-provider", true},
		{"dev provider token, DATA_PROVIDER_ROLE=provider", devRoles, "data-provider", "provider", true},
		{"dev provider token on provider", devRoles, "provider", "provider", true},
		{"local data-provider token", []string{"data-provider"}, "data-provider", "data-provider", true},
		{"local infra-provider token", []string{"infra-provider"}, "infra-provider", "data-provider", true},
		{"dev provider token on infra-provider", devRoles, "infra-provider", "data-provider", false},
		{"DX infra_provider token on infra-provider", []string{"infra_provider"}, "infra-provider", "provider", true},
		{"DX infra_provider token on data-provider", []string{"infra_provider"}, "data-provider", "provider", false},
		{"consumer only", []string{"consumer"}, "data-provider", "data-provider", false},
	}
	for _, c := range cases {
		if got := hasProviderKeyRole(c.roles, c.role, c.dpRole); got != c.want {
			t.Errorf("%s: hasProviderKeyRole(%v, %q, %q) = %v, want %v", c.name, c.roles, c.role, c.dpRole, got, c.want)
		}
	}
}
