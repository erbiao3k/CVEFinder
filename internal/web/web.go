package web

import (
	"context"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"CVEFinder/internal/cve"
	"CVEFinder/internal/store"
)

func Start(ctx context.Context, addr string, db *store.DB) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           Handler(db),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("网页服务停止: %v", err)
		}
	}()
	return nil
}

func Handler(db *store.DB) http.Handler {
	mux := http.NewServeMux()
	app := &webApp{db: db, pages: template.Must(template.New("pages").Funcs(template.FuncMap{
		"sevLabel":    cve.SeverityLabel,
		"displayTime": cve.DisplayTime,
		"refGroups":   cve.Groups,
		"refSummary":  cve.RefSummary,
		"snippet": func(s string) string {
			return cve.OneLine(s, 140)
		},
	}).Parse(pageTemplates))}
	mux.HandleFunc("GET /", app.list)
	mux.HandleFunc("GET /cve/{id}", app.detail)
	return mux
}

type webApp struct {
	db    *store.DB
	pages *template.Template
}

type listView struct {
	Records  []cve.Record
	Total    int
	Page     int
	Pages    int
	Severity string
	Product  string
	Query    string
	Products []string
	HasPrev  bool
	HasNext  bool
	PrevPage int
	NextPage int
}

func (a *webApp) list(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	filter := store.Filter{
		Severity: strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("severity"))),
		Product:  strings.TrimSpace(r.URL.Query().Get("product")),
		Query:    strings.TrimSpace(r.URL.Query().Get("q")),
		Page:     queryInt(r, "page"),
		Size:     50,
	}
	result, err := a.db.List(ctx, filter)
	if err != nil {
		http.Error(w, "读取数据失败", http.StatusInternalServerError)
		log.Printf("列表查询失败: %v", err)
		return
	}
	products, err := a.db.Products(ctx)
	if err != nil {
		http.Error(w, "读取数据失败", http.StatusInternalServerError)
		log.Printf("产品查询失败: %v", err)
		return
	}
	view := listView{
		Records:  result.Records,
		Total:    result.Total,
		Page:     result.Page,
		Pages:    result.Pages,
		Severity: filter.Severity,
		Product:  filter.Product,
		Query:    filter.Query,
		Products: products,
		HasPrev:  result.Page > 1,
		HasNext:  result.Page < result.Pages,
		PrevPage: result.Page - 1,
		NextPage: result.Page + 1,
	}
	a.render(w, "list", view)
}

func (a *webApp) detail(w http.ResponseWriter, r *http.Request) {
	record, ok, err := a.db.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "读取数据失败", http.StatusInternalServerError)
		log.Printf("详情查询失败: %v", err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	a.render(w, "detail", record)
}

func (a *webApp) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.pages.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("页面渲染失败: %v", err)
	}
}

func queryInt(r *http.Request, key string) int {
	n, _ := strconv.Atoi(r.URL.Query().Get(key))
	return n
}

const pageTemplates = `
{{define "style"}}
body{margin:0;font:14px/1.5 "Segoe UI",sans-serif;color:#1f2933;background:#f6f7f9}
header{padding:16px 24px;background:#111827;color:#fff}
header a{color:#fff;text-decoration:none}
main{padding:20px 24px;max-width:1100px;margin:0 auto}
form{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
input,select,button{font:inherit;padding:6px 8px}
table{width:100%;border-collapse:collapse;background:#fff}
th,td{padding:8px 10px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}
th{background:#f3f4f6}
.sev{display:inline-block;min-width:42px;padding:1px 6px;border-radius:4px;color:#fff;font-size:12px}
.CRITICAL{background:#b91c1c}.HIGH{background:#c2410c}.MEDIUM{background:#b45309}.LOW{background:#4b5563}
.empty{padding:24px;background:#fff;border:1px solid #e5e7eb}
.meta{color:#4b5563}
a{color:#1d4ed8}
.pager{margin-top:12px;display:flex;gap:12px;align-items:center}
.refs h2{font-size:16px;margin:18px 0 6px}
.refs li{margin:4px 0;word-break:break-all}
{{end}}
{{define "list"}}
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>CVEFinder</title><style>{{template "style"}}</style></head>
<body>
<header><a href="/">CVEFinder</a></header>
<main>
<form method="get" action="/">
<select name="severity">
<option value="">全部等级</option>
<option value="CRITICAL" {{if eq .Severity "CRITICAL"}}selected{{end}}>严重</option>
<option value="HIGH" {{if eq .Severity "HIGH"}}selected{{end}}>高危</option>
<option value="MEDIUM" {{if eq .Severity "MEDIUM"}}selected{{end}}>中危</option>
<option value="LOW" {{if eq .Severity "LOW"}}selected{{end}}>低危</option>
</select>
<select name="product">
<option value="">全部产品</option>
{{range .Products}}<option value="{{.}}" {{if eq . $.Product}}selected{{end}}>{{.}}</option>{{end}}
</select>
<input name="q" value="{{.Query}}" placeholder="搜索编号或描述">
<button type="submit">筛选</button>
</form>
<p class="meta">共 {{.Total}} 条</p>
{{if .Records}}
<table>
<thead><tr><th>等级</th><th>编号</th><th>产品</th><th>分数</th><th>更新</th><th>参考</th><th>描述</th></tr></thead>
<tbody>
{{range .Records}}
<tr>
<td><span class="sev {{.Severity}}">{{sevLabel .Severity}}</span></td>
<td><a href="/cve/{{.ID}}">{{.ID}}</a></td>
<td>{{range $i, $p := .Products}}{{if $i}}、{{end}}{{$p}}{{end}}</td>
<td>{{printf "%.1f" .Score}}</td>
<td>{{displayTime .Modified}}</td>
<td>{{refSummary .References}}</td>
<td>{{snippet .Summary}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p class="empty">没有符合条件的漏洞。启动后的第一次拉取会写入最近 7 天的数据。</p>
{{end}}
<div class="pager">
{{if .HasPrev}}<a href="/?severity={{.Severity}}&product={{.Product}}&q={{.Query}}&page={{.PrevPage}}">上一页</a>{{end}}
<span>{{.Page}} / {{.Pages}}</span>
{{if .HasNext}}<a href="/?severity={{.Severity}}&product={{.Product}}&q={{.Query}}&page={{.NextPage}}">下一页</a>{{end}}
</div>
</main>
</body>
</html>
{{end}}
{{define "detail"}}
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>{{.ID}}</title><style>{{template "style"}}</style></head>
<body>
<header><a href="/">CVEFinder</a></header>
<main>
<p><a href="/">返回列表</a></p>
<h1>{{.ID}}</h1>
<p><span class="sev {{.Severity}}">{{sevLabel .Severity}}</span> {{printf "%.1f" .Score}}</p>
<p>产品：{{range $i, $p := .Products}}{{if $i}}、{{end}}{{$p}}{{end}}</p>
<p class="meta">状态 {{.Status}} · 发布 {{displayTime .Published}} · 更新 {{displayTime .Modified}}</p>
<p>{{.Summary}}</p>
<div class="refs">
{{range refGroups .References}}
<h2>{{.Title}}</h2>
<ul>
{{range .Links}}<li><a href="{{.URL}}">{{.URL}}</a></li>{{end}}
</ul>
{{else}}
<p class="meta">暂无补丁、缓解措施或厂商公告。</p>
{{end}}
</div>
<p><a href="{{.URL}}">NVD 原文</a></p>
</main>
</body>
</html>
{{end}}
`
