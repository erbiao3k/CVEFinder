package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"CVEFinder/internal/cve"
)

func TestDBUpsertAndFilter(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "cve.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	err = db.Upsert(ctx, []cve.Record{
		{ID: "CVE-2024-1000", Severity: "CRITICAL", Score: 9.8, Products: []string{"Nginx"}, Summary: "nginx issue", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1000"},
		{ID: "CVE-2024-1001", Severity: "HIGH", Score: 8, Products: []string{"Nginx", "Linux 内核"}, Summary: "kernel issue", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1001"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.List(ctx, Filter{Product: "Linux 内核", Size: 50, Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || result.Records[0].ID != "CVE-2024-1001" {
		t.Fatalf("%+v", result)
	}
	got, ok, err := db.Get(ctx, "cve-2024-1000")
	if err != nil || !ok || !strings.Contains(cve.JoinProducts(got.Products), "Nginx") {
		t.Fatalf("got %+v ok %v err %v", got, ok, err)
	}
}
