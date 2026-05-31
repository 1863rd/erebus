// Package openapi discovers OpenAPI/Swagger specs and generates synthetic
// crawler pages for each endpoint so injection modules can test them.
package openapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/erebus/scanner/internal/client"
	"github.com/erebus/scanner/internal/crawler"
)

var specPaths = []string{
	"/swagger.json",
	"/swagger/v2/swagger.json",
	"/swagger/v1/swagger.json",
	"/openapi.json",
	"/openapi.yaml",
	"/api-docs",
	"/api-docs/swagger.json",
	"/api/swagger.json",
	"/api/openapi.json",
	"/v1/swagger.json",
	"/v2/swagger.json",
	"/v3/swagger.json",
	"/api/v1/swagger.json",
	"/api/v2/swagger.json",
	"/api/v3/swagger.json",
	"/api/v1/openapi.json",
	"/.well-known/openapi.json",
	"/docs/openapi.json",
	"/docs/swagger.json",
	"/swagger-ui.html",
	"/swagger-ui",
}

// swagger2 is a minimal Swagger 2.x structure.
type swagger2 struct {
	Swagger  string `json:"swagger"`
	Host     string `json:"host"`
	BasePath string `json:"basePath"`
	Paths    map[string]map[string]swaggerOp `json:"paths"`
}

// openapi3 is a minimal OpenAPI 3.x structure.
type openapi3 struct {
	OpenAPI string `json:"openapi"`
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Paths map[string]map[string]swaggerOp `json:"paths"`
}

type swaggerOp struct {
	OperationID string       `json:"operationId"`
	Parameters  []apiParam   `json:"parameters"`
	Summary     string       `json:"summary"`
	RequestBody *requestBody `json:"requestBody"`
}

type apiParam struct {
	Name     string `json:"name"`
	In       string `json:"in"` // query, header, path, cookie
	Required bool   `json:"required"`
	Schema   struct {
		Type    string `json:"type"`
		Example interface{} `json:"example"`
	} `json:"schema"`
	Example interface{} `json:"example"`
}

type requestBody struct {
	Content map[string]struct {
		Schema struct {
			Properties map[string]struct {
				Type    string      `json:"type"`
				Example interface{} `json:"example"`
			} `json:"properties"`
			Example interface{} `json:"example"`
		} `json:"schema"`
		Example interface{} `json:"example"`
	} `json:"content"`
}

// Discover probes the target for an OpenAPI/Swagger spec and returns synthetic
// crawler pages for each documented endpoint. Returns nil if no spec is found.
func Discover(ctx context.Context, c *client.Client, targetURL string) ([]crawler.Page, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	base := u.Scheme + "://" + u.Host

	for _, path := range specPaths {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		specURL := base + path
		body, err := fetchJSON(ctx, c, specURL)
		if err != nil || len(body) == 0 {
			continue
		}

		// Try Swagger 2.x
		if pages := parseSwagger2(base, body); len(pages) > 0 {
			fmt.Printf("  [openapi] Swagger 2.x spec found at %s — %d endpoints\n", specURL, len(pages))
			return pages, nil
		}

		// Try OpenAPI 3.x
		if pages := parseOpenAPI3(base, body); len(pages) > 0 {
			fmt.Printf("  [openapi] OpenAPI 3.x spec found at %s — %d endpoints\n", specURL, len(pages))
			return pages, nil
		}

		// Try to extract spec URL from swagger-ui HTML page
		if strings.Contains(string(body), "swagger") || strings.Contains(string(body), "openapi") {
			if specURL2 := extractSpecURL(base, string(body)); specURL2 != "" && specURL2 != specURL {
				if body2, err := fetchJSON(ctx, c, specURL2); err == nil && len(body2) > 0 {
					if pages := parseSwagger2(base, body2); len(pages) > 0 {
						fmt.Printf("  [openapi] Swagger spec found via UI at %s — %d endpoints\n", specURL2, len(pages))
						return pages, nil
					}
					if pages := parseOpenAPI3(base, body2); len(pages) > 0 {
						fmt.Printf("  [openapi] OpenAPI spec found via UI at %s — %d endpoints\n", specURL2, len(pages))
						return pages, nil
					}
				}
			}
		}
	}
	return nil, nil
}

func parseSwagger2(base string, data []byte) []crawler.Page {
	var spec swagger2
	if err := json.Unmarshal(data, &spec); err != nil || spec.Swagger == "" {
		return nil
	}

	specBase := base
	if spec.Host != "" {
		specBase = "https://" + spec.Host
	}
	if spec.BasePath != "" && spec.BasePath != "/" {
		specBase += spec.BasePath
	}

	return buildPages(specBase, spec.Paths)
}

func parseOpenAPI3(base string, data []byte) []crawler.Page {
	var spec openapi3
	if err := json.Unmarshal(data, &spec); err != nil || spec.OpenAPI == "" {
		return nil
	}

	specBase := base
	if len(spec.Servers) > 0 && spec.Servers[0].URL != "" {
		srv := spec.Servers[0].URL
		if strings.HasPrefix(srv, "/") {
			specBase = base + srv
		} else if strings.HasPrefix(srv, "http") {
			specBase = srv
		}
	}

	return buildPages(specBase, spec.Paths)
}

func buildPages(base string, paths map[string]map[string]swaggerOp) []crawler.Page {
	var pages []crawler.Page

	for apiPath, methods := range paths {
		for method, op := range methods {
			method = strings.ToUpper(method)
			if method == "HEAD" || method == "OPTIONS" {
				continue
			}

			// Build URL with placeholder values for path parameters
			filledPath := apiPath
			queryParams := url.Values{}
			var formFields []crawler.Field

			for _, p := range op.Parameters {
				placeholder := paramPlaceholder(p)
				switch p.In {
				case "path":
					filledPath = strings.ReplaceAll(filledPath, "{"+p.Name+"}", placeholder)
				case "query":
					queryParams.Set(p.Name, placeholder)
				}
			}

			// Extract form fields from request body
			if op.RequestBody != nil {
				for _, ct := range op.RequestBody.Content {
					for propName, prop := range ct.Schema.Properties {
						val := ""
						if prop.Example != nil {
							val = fmt.Sprintf("%v", prop.Example)
						}
						formFields = append(formFields, crawler.Field{
							Name:  propName,
							Value: val,
							Type:  prop.Type,
						})
					}
					break // use first content type only
				}
			}

			pageURL := base + filledPath
			if len(queryParams) > 0 {
				pageURL += "?" + queryParams.Encode()
			}

			page := crawler.Page{URL: pageURL}
			if method == "POST" || method == "PUT" || method == "PATCH" {
				formMethod := method
				page.Forms = []crawler.Form{{
					Action: base + filledPath,
					Method: formMethod,
					Fields: formFields,
				}}
			}

			pages = append(pages, page)
		}
	}
	return pages
}

func paramPlaceholder(p apiParam) string {
	if p.Example != nil {
		return fmt.Sprintf("%v", p.Example)
	}
	if p.Schema.Example != nil {
		return fmt.Sprintf("%v", p.Schema.Example)
	}
	switch p.Schema.Type {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	default:
		return "test"
	}
}

func fetchJSON(ctx context.Context, c *client.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json,application/yaml,*/*")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := client.ReadBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, nil
	}
	return body, nil
}

// extractSpecURL tries to find a JSON spec URL embedded in a swagger-ui HTML page.
func extractSpecURL(base, html string) string {
	lower := strings.ToLower(html)
	for _, marker := range []string{`"url":"`, `'url':'`, `url: "`, `url: '`} {
		idx := strings.Index(lower, marker)
		if idx == -1 {
			continue
		}
		start := idx + len(marker)
		end := strings.IndexAny(html[start:], `"'`)
		if end <= 0 {
			continue
		}
		rawURL := html[start : start+end]
		if strings.Contains(rawURL, "swagger") || strings.Contains(rawURL, "openapi") || strings.Contains(rawURL, "api-docs") {
			if strings.HasPrefix(rawURL, "/") {
				return base + rawURL
			}
			if strings.HasPrefix(rawURL, "http") {
				return rawURL
			}
		}
	}
	return ""
}
