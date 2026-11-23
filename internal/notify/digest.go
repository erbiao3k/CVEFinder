package notify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"CVEFinder/internal/cve"
)

type Hit struct {
	ID       string
	Severity string
	Score    float64
	Products []string
}

func Sort(hits []Hit) {
	sort.Slice(hits, func(i, j int) bool {
		ri, rj := severityRank(hits[i].Severity), severityRank(hits[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].ID < hits[j].ID
	})
}

func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func digestTitle(start, end time.Time) string {
	if end.Sub(start) >= 24*time.Hour {
		return "漏洞启动报告"
	}
	return "漏洞例行报告"
}

func Summary(start, end time.Time, hits []Hit, watched int, pageURL string) string {
	window := fmt.Sprintf("%s ~ %s UTC", start.Format("2006-01-02 15:04"), end.Format("2006-01-02 15:04"))
	title := digestTitle(start, end)
	if len(hits) == 0 {
		scope := "本时段"
		if days := int(end.Sub(start).Round(time.Hour).Hours()) / 24; days >= 1 {
			scope = fmt.Sprintf("近 %d 天", days)
		}
		return fmt.Sprintf("%s\n%s没有新增匹配漏洞。\n窗口 %s\n监听 %d 个产品\n详情 %s", title, scope, window, watched, pageURL)
	}
	counts := map[string]int{}
	productCounts := map[string]int{}
	for _, hit := range hits {
		counts[strings.ToUpper(hit.Severity)]++
		for _, product := range hit.Products {
			productCounts[product]++
		}
	}
	var summary []string
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if counts[severity] == 0 {
			continue
		}
		summary = append(summary, fmt.Sprintf("%s %d", cve.SeverityLabel(severity), counts[severity]))
	}
	if counts[""] > 0 {
		summary = append(summary, fmt.Sprintf("未评分 %d", counts[""]))
	}
	return fmt.Sprintf("%s · 新增 %d 条\n窗口 %s\n%s\n涉及 %s\n详情 %s",
		title, len(hits), window, strings.Join(summary, "，"), formatProductCounts(productCounts), pageURL)
}

func formatProductCounts(counts map[string]int) string {
	type item struct {
		name  string
		count int
	}
	items := make([]item, 0, len(counts))
	for name, count := range counts {
		items = append(items, item{name: name, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].name < items[j].name
	})
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s %d", item.name, item.count))
	}
	return strings.Join(parts, "、")
}
