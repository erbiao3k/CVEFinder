package watch

import (
	"strings"

	"CVEFinder/internal/nvd"
)

// Product 是一条监听项。Keys 是 NVD CPE 的「厂商:产品」，不比较版本。
// Prefixes 用于一个组件拆成很多 CPE 产品名的情况，只匹配产品名前缀。
type Product struct {
	Name     string
	Keys     []string
	Prefixes []string
}

type prefixRule struct {
	name   string
	prefix string
}

type Watcher struct {
	byKey    map[string]string
	prefixes []prefixRule
	order    []string
}

func Default() []Product {
	return []Product{
		{Name: "Nginx", Keys: []string{"nginx:nginx", "f5:nginx"}},
		{Name: "Ubuntu", Keys: []string{"canonical:ubuntu_linux"}},
		{Name: "Alpine", Keys: []string{"alpinelinux:alpine_linux"}},
		{Name: "CentOS", Keys: []string{"centos:centos", "redhat:enterprise_linux"}},
		{Name: "Linux 内核", Keys: []string{"linux:linux_kernel"}},
		{Name: "Windows", Keys: []string{
			"microsoft:windows_10",
			"microsoft:windows_11",
			"microsoft:windows_server_2016",
			"microsoft:windows_server_2019",
			"microsoft:windows_server_2022",
			"microsoft:windows_server_2025",
		}},
		{Name: "Java", Keys: []string{"oracle:jdk", "oracle:jre", "oracle:openjdk", "eclipse:temurin"}},
		{Name: "Node.js", Keys: []string{"nodejs:node.js"}},
		{Name: "PHP", Keys: []string{"php:php"}},
		{Name: "Python", Keys: []string{"python:python"}},
		{Name: "Go", Keys: []string{"golang:go"}},
		{Name: "MySQL", Keys: []string{"oracle:mysql"}},
		{Name: "MongoDB", Keys: []string{"mongodb:mongodb"}},
		{Name: "Redis", Keys: []string{"redis:redis"}},
		{Name: "Elasticsearch", Keys: []string{"elastic:elasticsearch"}},
		{Name: "Nacos", Keys: []string{"alibaba:nacos"}},
		{Name: "XXL-JOB", Keys: []string{"xuxueli:xxl-job"}},
		{Name: "Gitea", Keys: []string{"gitea:gitea"}},
		{Name: "Jenkins", Keys: []string{"jenkins:jenkins"}},
		{Name: "Docker", Keys: []string{"docker:docker"}},
		{Name: "Kubernetes", Keys: []string{"kubernetes:kubernetes"}},
		{Name: "containerd", Keys: []string{"linuxfoundation:containerd"}},
		{Name: "RabbitMQ", Keys: []string{"pivotal_software:rabbitmq", "vmware:rabbitmq", "broadcom:rabbitmq"}},
		{Name: "Kafka", Keys: []string{"apache:kafka"}},
		{Name: "OpenVPN", Keys: []string{"openvpn:openvpn", "openvpn:openvpn_access_server"}},
		{Name: "OpenTelemetry", Prefixes: []string{"cncf:opentelemetry", "linuxfoundation:opentelemetry"}},
		{Name: "OpenObserve", Keys: []string{"openobserve:openobserve"}},
		{Name: "JumpServer", Keys: []string{"fit2cloud:jumpserver"}},
	}
}

func New(products []Product) *Watcher {
	w := &Watcher{byKey: map[string]string{}}
	seen := map[string]bool{}
	for _, product := range products {
		if product.Name != "" && !seen[product.Name] {
			w.order = append(w.order, product.Name)
			seen[product.Name] = true
		}
		for _, key := range product.Keys {
			w.byKey[strings.ToLower(strings.TrimSpace(key))] = product.Name
		}
		for _, prefix := range product.Prefixes {
			w.prefixes = append(w.prefixes, prefixRule{
				name:   product.Name,
				prefix: strings.ToLower(strings.TrimSpace(prefix)),
			})
		}
	}
	return w
}

func (w *Watcher) Names() []string {
	out := make([]string, len(w.order))
	copy(out, w.order)
	return out
}

func (w *Watcher) Match(cve nvd.CVE) []string {
	found := map[string]struct{}{}
	var walk func([]nvd.Node)
	walk = func(nodes []nvd.Node) {
		for _, n := range nodes {
			for _, match := range n.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				name, ok := w.matchCriteria(match.Criteria)
				if ok {
					found[name] = struct{}{}
				}
			}
			walk(n.Children)
		}
	}
	for _, cfg := range cve.Configurations {
		walk(cfg.Nodes)
	}
	if len(found) == 0 {
		return nil
	}
	var names []string
	for _, name := range w.order {
		if _, ok := found[name]; ok {
			names = append(names, name)
		}
	}
	return names
}

func (w *Watcher) matchCriteria(criteria string) (string, bool) {
	key, ok := cpeProductKey(criteria)
	if !ok {
		return "", false
	}
	if name, ok := w.byKey[key]; ok {
		return name, true
	}
	for _, rule := range w.prefixes {
		if productPrefix(key, rule.prefix) {
			return rule.name, true
		}
	}
	return "", false
}

func cpeProductKey(criteria string) (string, bool) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 5 || !strings.EqualFold(parts[0], "cpe") {
		return "", false
	}
	vendor := strings.ToLower(parts[3])
	product := strings.ToLower(parts[4])
	if vendor == "" || vendor == "*" || product == "" || product == "*" {
		return "", false
	}
	return vendor + ":" + product, true
}

func productPrefix(key, prefix string) bool {
	if key == prefix {
		return true
	}
	if !strings.HasPrefix(key, prefix) || len(key) <= len(prefix) {
		return false
	}
	switch key[len(prefix)] {
	case '-', '_':
		return true
	default:
		return false
	}
}
