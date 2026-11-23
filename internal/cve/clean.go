package cve

import (
	"regexp"
	"strings"
	"time"

	"CVEFinder/internal/nvd"
)

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

type Record struct {
	ID         string
	Severity   string
	Score      float64
	Products   []string
	Summary    string
	Status     string
	Published  string
	Modified   string
	URL        string
	References []Reference
}

type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

func Clean(item nvd.CVE, products []string) (Record, bool) {
	id := strings.ToUpper(strings.TrimSpace(item.ID))
	if !cveIDPattern.MatchString(id) || len(products) == 0 {
		return Record{}, false
	}
	if strings.EqualFold(strings.TrimSpace(item.VulnStatus), "Rejected") {
		return Record{}, false
	}
	severity, score := item.Severity()
	switch severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
	default:
		severity = ""
	}
	return Record{
		ID:         id,
		Severity:   severity,
		Score:      score,
		Products:   products,
		Summary:    OneLine(item.Description(), 4000),
		Status:     OneLine(item.VulnStatus, 40),
		Published:  normalizeTime(item.Published),
		Modified:   normalizeTime(item.LastModified),
		URL:        "https://nvd.nist.gov/vuln/detail/" + id,
		References: cleanReferences(item.References),
	}, true
}

func cleanReferences(items []nvd.Ref) []Reference {
	kept := map[string]map[string]struct{}{}
	var order []string
	for _, item := range items {
		link := strings.TrimSpace(item.URL)
		if !strings.HasPrefix(link, "https://") && !strings.HasPrefix(link, "http://") {
			continue
		}
		tags := map[string]struct{}{}
		for _, tag := range item.Tags {
			if canonical, ok := canonicalRefTag(tag); ok {
				tags[canonical] = struct{}{}
			}
		}
		if len(tags) == 0 {
			continue
		}
		if _, ok := kept[link]; !ok {
			kept[link] = map[string]struct{}{}
			order = append(order, link)
		}
		for tag := range tags {
			kept[link][tag] = struct{}{}
		}
	}
	refs := make([]Reference, 0, len(order))
	for _, link := range order {
		refs = append(refs, Reference{URL: link, Tags: orderedRefTags(kept[link])})
	}
	return refs
}

func canonicalRefTag(tag string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "patch":
		return "Patch", true
	case "mitigation":
		return "Mitigation", true
	case "vendor advisory":
		return "Vendor Advisory", true
	default:
		return "", false
	}
}

func orderedRefTags(tags map[string]struct{}) []string {
	var out []string
	for _, tag := range []string{"Patch", "Mitigation", "Vendor Advisory"} {
		if _, ok := tags[tag]; ok {
			out = append(out, tag)
		}
	}
	return out
}

type Group struct {
	Title string
	Links []Reference
}

func Groups(refs []Reference) []Group {
	order := []struct {
		tag   string
		title string
	}{
		{"Patch", "补丁"},
		{"Mitigation", "缓解措施"},
		{"Vendor Advisory", "厂商公告"},
	}
	var groups []Group
	for _, item := range order {
		var links []Reference
		for _, ref := range refs {
			for _, tag := range ref.Tags {
				if tag == item.tag {
					links = append(links, ref)
					break
				}
			}
		}
		if len(links) > 0 {
			groups = append(groups, Group{Title: item.title, Links: links})
		}
	}
	return groups
}

func RefSummary(refs []Reference) string {
	groups := Groups(refs)
	if len(groups) == 0 {
		return "—"
	}
	titles := make([]string, 0, len(groups))
	for _, group := range groups {
		titles = append(titles, group.Title)
	}
	return strings.Join(titles, "、")
}

func normalizeTime(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000", "2006-01-02T15:04:05"}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
	}
	return raw
}

func JoinProducts(products []string) string {
	return strings.Join(products, "、")
}

func SplitProducts(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, "、")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func SeverityLabel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "严重"
	case "HIGH":
		return "高危"
	case "MEDIUM":
		return "中危"
	case "LOW":
		return "低危"
	default:
		return "未评分"
	}
}

func OneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.NewReplacer("[", "［", "]", "］").Replace(s)
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

func DisplayTime(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return parsed.In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04")
}
