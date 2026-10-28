package workload

import "testing"

func TestPolicyAllowsWorkload(t *testing.T) {
	withList := func(list ...interface{}) map[string]interface{} {
		return map[string]interface{}{"rules": map[string]interface{}{"allowed_workloads": list}}
	}
	cases := []struct {
		name   string
		policy map[string]interface{}
		id     string
		want   bool
	}{
		{"no rules", map[string]interface{}{}, "credits-evaluation", true},
		{"no list", map[string]interface{}{"rules": map[string]interface{}{}}, "credits-evaluation", true},
		{"empty list", withList(), "credits-evaluation", true},
		{"listed object", withList(map[string]interface{}{"id": "credits-evaluation", "name": "Credits Evaluation"}), "credits-evaluation", true},
		{"listed string", withList("market-offer-generation"), "market-offer-generation", true},
		{"not listed", withList(map[string]interface{}{"id": "market-offer-generation"}), "credits-evaluation", false},
		{"blank id not listed", withList(map[string]interface{}{"id": "credits-evaluation"}), "", false},
	}
	for _, c := range cases {
		if got := PolicyAllowsWorkload(c.policy, c.id); got != c.want {
			t.Errorf("%s: PolicyAllowsWorkload(%q) = %v, want %v", c.name, c.id, got, c.want)
		}
	}
}
