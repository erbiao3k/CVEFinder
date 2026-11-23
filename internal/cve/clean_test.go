package cve

import (
	"testing"

	"CVEFinder/internal/nvd"
)

func TestCleanRecord(t *testing.T) {
	var metric nvd.Metric
	metric.CVSSData.BaseScore = 9.8
	metric.CVSSData.BaseSeverity = "CRITICAL"
	record, ok := Clean(nvd.CVE{
		ID:           " cve-2024-12345 ",
		VulnStatus:   "Analyzed",
		Published:    "2024-03-01T00:00:00.000",
		LastModified: "2024-03-02T01:02:03Z",
		Descriptions: []nvd.Text{{Lang: "en", Value: "  line\nbreak  "}},
		Metrics:      nvd.Metrics{V31: []nvd.Metric{metric}},
	}, []string{"Nginx"})
	if !ok {
		t.Fatal("expected record")
	}
	if record.ID != "CVE-2024-12345" || record.Severity != "CRITICAL" || record.Summary != "line break" {
		t.Fatalf("%+v", record)
	}
	cleaned := cleanReferences([]nvd.Ref{
		{URL: " https://example.com/patch ", Tags: []string{"Patch", "Vendor Advisory"}},
		{URL: "https://example.com/notes", Tags: []string{"Third Party Advisory"}},
		{URL: "ftp://example.com/file", Tags: []string{"Patch"}},
		{URL: "https://example.com/workaround", Tags: []string{"mitigation"}},
	})
	if len(cleaned) != 2 || cleaned[0].URL != "https://example.com/patch" || len(cleaned[0].Tags) != 2 {
		t.Fatalf("refs = %+v", cleaned)
	}
	if RefSummary(cleaned) != "补丁、缓解措施、厂商公告" {
		t.Fatalf("summary = %s", RefSummary(cleaned))
	}
	if _, ok := Clean(nvd.CVE{ID: "CVE-2024-1", VulnStatus: "Rejected"}, []string{"Nginx"}); ok {
		t.Fatal("rejected id should be dropped")
	}
}
