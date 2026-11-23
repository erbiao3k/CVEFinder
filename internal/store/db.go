package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"CVEFinder/internal/cve"

	_ "modernc.org/sqlite"
)

const cveColumns = "id, severity, score, products, summary, status, published, modified, url, ref_links"

type DB struct {
	sql *sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=rwc")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `
		PRAGMA journal_mode=WAL;
		PRAGMA busy_timeout=5000;
		CREATE TABLE IF NOT EXISTS cves (
			id TEXT PRIMARY KEY,
			severity TEXT NOT NULL DEFAULT '',
			score REAL NOT NULL DEFAULT 0,
			products TEXT NOT NULL,
			summary TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT '',
			published TEXT NOT NULL DEFAULT '',
			modified TEXT NOT NULL DEFAULT '',
			url TEXT NOT NULL,
			ref_links TEXT NOT NULL DEFAULT '[]',
			first_seen TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
	`); err != nil {
		db.Close()
		return nil, err
	}
	if err := ensureColumn(ctx, db, "ref_links", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{sql: db}, nil
}

func ensureColumn(ctx context.Context, db *sql.DB, name, decl string) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(cves)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var colName, colType string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &pk); err != nil {
			return err
		}
		if colName == name {
			return rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `ALTER TABLE cves ADD COLUMN `+name+` `+decl)
	return err
}

func (d *DB) Close() error {
	return d.sql.Close()
}

func (d *DB) Upsert(ctx context.Context, records []cve.Record) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO cves (id, severity, score, products, summary, status, published, modified, url, ref_links, first_seen, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			severity=excluded.severity,
			score=excluded.score,
			products=excluded.products,
			summary=excluded.summary,
			status=excluded.status,
			published=excluded.published,
			modified=excluded.modified,
			url=excluded.url,
			ref_links=excluded.ref_links,
			updated_at=excluded.updated_at
	`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, record := range records {
		if _, err := stmt.ExecContext(ctx, record.ID, record.Severity, record.Score, cve.JoinProducts(record.Products), record.Summary, record.Status, record.Published, record.Modified, record.URL, encodeRefs(record.References), now, now); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

type Filter struct {
	Severity string
	Product  string
	Query    string
	Page     int
	Size     int
}

type ListResult struct {
	Records []cve.Record
	Total   int
	Page    int
	Pages   int
}

func (d *DB) List(ctx context.Context, filter Filter) (ListResult, error) {
	if filter.Size <= 0 {
		filter.Size = 50
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}
	where, args := filterSQL(filter)
	var total int
	if err := d.sql.QueryRowContext(ctx, "SELECT COUNT(*) FROM cves"+where, args...).Scan(&total); err != nil {
		return ListResult{}, err
	}
	pages := (total + filter.Size - 1) / filter.Size
	if pages == 0 {
		pages = 1
	}
	if filter.Page > pages {
		filter.Page = pages
	}
	args = append(args, filter.Size, (filter.Page-1)*filter.Size)
	rows, err := d.sql.QueryContext(ctx, `
		SELECT `+cveColumns+`
		FROM cves`+where+`
		ORDER BY
			CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
			score DESC,
			modified DESC,
			id DESC
		LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()
	var records []cve.Record
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return ListResult{}, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, err
	}
	return ListResult{Records: records, Total: total, Page: filter.Page, Pages: pages}, nil
}

func (d *DB) Get(ctx context.Context, id string) (cve.Record, bool, error) {
	row := d.sql.QueryRowContext(ctx, `
		SELECT `+cveColumns+`
		FROM cves WHERE id = ?`, strings.ToUpper(strings.TrimSpace(id)))
	record, err := scanRecord(row)
	if err == sql.ErrNoRows {
		return cve.Record{}, false, nil
	}
	if err != nil {
		return cve.Record{}, false, err
	}
	return record, true, nil
}

func (d *DB) Products(ctx context.Context) ([]string, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT products FROM cves`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]struct{}{}
	var names []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		for _, name := range cve.SplitProducts(raw) {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRecord(row scanner) (cve.Record, error) {
	var record cve.Record
	var products, refs string
	if err := row.Scan(&record.ID, &record.Severity, &record.Score, &products, &record.Summary, &record.Status, &record.Published, &record.Modified, &record.URL, &refs); err != nil {
		return cve.Record{}, err
	}
	record.Products = cve.SplitProducts(products)
	record.References = decodeRefs(refs)
	return record, nil
}

func encodeRefs(refs []cve.Reference) string {
	if len(refs) == 0 {
		return "[]"
	}
	body, err := json.Marshal(refs)
	if err != nil {
		return "[]"
	}
	return string(body)
}

func decodeRefs(raw string) []cve.Reference {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var refs []cve.Reference
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return nil
	}
	return refs
}

func filterSQL(filter Filter) (string, []any) {
	var clauses []string
	var args []any
	if filter.Severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, strings.ToUpper(filter.Severity))
	}
	if filter.Product != "" {
		clauses = append(clauses, "(products = ? OR products LIKE ? OR products LIKE ? OR products LIKE ?)")
		args = append(args, filter.Product, filter.Product+"、%", "%、"+filter.Product+"、%", "%、"+filter.Product)
	}
	if q := strings.TrimSpace(filter.Query); q != "" {
		clauses = append(clauses, "(id LIKE ? OR summary LIKE ? OR products LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}
