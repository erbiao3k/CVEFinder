package nvd

import "testing"

func TestParseNVD(t *testing.T) {
	body := []byte(`{
		"totalResults": 1,
		"vulnerabilities": [
			{"cve": {
				"id": "CVE-2024-9",
				"vulnStatus": "Analyzed",
				"descriptions": [{"lang": "en", "value": "demo"}],
				"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
				"configurations": [{"nodes": [{"cpeMatch": [
					{"vulnerable": true, "criteria": "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*"}
				]}]}]
			}}
		]
	}`)
	page, err := parseNVD(body)
	if err != nil {
		t.Fatal(err)
	}
	if page.total != 1 || len(page.items) != 1 || page.items[0].ID != "CVE-2024-9" {
		t.Fatalf("page = %+v", page)
	}
	severity, score := page.items[0].Severity()
	if severity != "CRITICAL" || score != 9.8 {
		t.Fatalf("severity %s score %v", severity, score)
	}
}
