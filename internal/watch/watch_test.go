package watch

import (
	"testing"

	"CVEFinder/internal/nvd"
)

func TestMatchIgnoresVersionAndNonVulnerable(t *testing.T) {
	watcher := New(Default())
	item := nvd.CVE{
		ID: "CVE-2024-0001",
		Configurations: []nvd.Configuration{{
			Nodes: []nvd.Node{{
				CPEMatch: []nvd.CPEMatch{
					{Vulnerable: false, Criteria: "cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*"},
					{Vulnerable: true, Criteria: "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"},
					{Vulnerable: true, Criteria: "cpe:2.3:a:nodejs:node.js:20.10.0:*:*:*:*:*:*:*"},
					{Vulnerable: true, Criteria: "cpe:2.3:a:cncf:opentelemetry-collector:0.90.0:*:*:*:*:*:*:*"},
				},
			}},
		}},
	}

	got := watcher.Match(item)
	want := []string{"Nginx", "Node.js", "OpenTelemetry"}
	if len(got) != len(want) {
		t.Fatalf("match = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("match = %v, want %v", got, want)
		}
	}
}
