package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	// Also match JS loaded via link[rel=modulepreload] or similar
	moduleLinkRe = regexp.MustCompile(`<link[^>]+href=["']([^"']+\.(?:js|mjs))["']`)
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// ScanURL fetches a webpage and checks all its scripts for source maps.
// If probe is true, it also tries appending .map to every JS URL even without hints.
func ScanURL(rawURL string, probe bool) (*URLResult, error) {
	// Ensure scheme
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	baseURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	result := &URLResult{
		URL: rawURL,
	}

	// Fetch the page
	html, err := fetchBody(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetching page: %w", err)
	}

	// Extract script URLs
	scriptURLs := extractScriptURLs(html, baseURL)
	result.ScriptsFound = len(scriptURLs)

	// Scan each script
	for _, scriptURL := range scriptURLs {
		info := scanScript(scriptURL, baseURL, probe)
		result.Scripts = append(result.Scripts, info)
		result.ScriptsScanned++
		if info.MapAccessible {
			result.MapsExposed++
			result.TotalLinesExposed += info.LinesExposed
			result.TotalSourceFiles += info.SourcesCount
		}
		if info.InlineMap {
			result.MapsExposed++
			result.TotalLinesExposed += info.LinesExposed
			result.TotalSourceFiles += info.SourcesCount
		}
	}

	// Build findings
	if result.MapsExposed > 0 {
		result.Status = "EXPOSED"
		result.Findings = append(result.Findings,
			fmt.Sprintf("%d source map(s) accessible on the live site", result.MapsExposed))
		if result.TotalLinesExposed > 0 {
			result.Findings = append(result.Findings,
				fmt.Sprintf("~%s lines of source code recoverable across %d files",
					FormatNumber(result.TotalLinesExposed), result.TotalSourceFiles))
		}
	} else {
		result.Status = "CLEAN"
		result.Findings = append(result.Findings, "No exposed source maps found")
	}

	return result, nil
}

func extractScriptURLs(html string, baseURL *url.URL) []string {
	seen := make(map[string]bool)
	var urls []string

	for _, re := range []*regexp.Regexp{scriptSrcRe, moduleLinkRe} {
		for _, match := range re.FindAllStringSubmatch(html, -1) {
			src := match[1]
			resolved := resolveURL(src, baseURL)
			if resolved != "" && !seen[resolved] {
				seen[resolved] = true
				urls = append(urls, resolved)
			}
		}
	}

	return urls
}

func resolveURL(ref string, base *url.URL) string {
	if strings.HasPrefix(ref, "data:") {
		return ""
	}
	parsed, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(parsed).String()
}

func scanScript(scriptURL string, baseURL *url.URL, probe bool) ScriptInfo {
	info := ScriptInfo{URL: scriptURL}

	jsBody, err := fetchBody(scriptURL)
	if err != nil {
		// Even if we can't fetch the JS, try probing for .map
		if probe {
			probeMapURL(scriptURL, &info)
		}
		return info
	}

	// Check for inline source map
	if inlineData := extractInlineSourceMap(jsBody); inlineData != nil {
		info.InlineMap = true
		info.HasMapRef = true
		var sm sourceMapJSON
		if json.Unmarshal(inlineData, &sm) == nil {
			info.SourcesCount = len(sm.Sources)
			for _, sc := range sm.SourcesContent {
				if strings.TrimSpace(sc) != "" {
					info.HasSourceContent = true
					info.LinesExposed += strings.Count(sc, "\n") + 1
				}
			}
		}
		return info
	}

	// Check for external sourceMappingURL
	mapRef := ExtractExternalMapRef(jsBody)
	if mapRef == "" {
		// Also try the SourceMap HTTP header
		mapRef = fetchSourceMapHeader(scriptURL)
	}

	if mapRef != "" {
		info.HasMapRef = true
		mapFullURL := resolveMapURL(mapRef, scriptURL, baseURL)
		info.MapURL = mapFullURL
		tryFetchMap(mapFullURL, &info)
		return info
	}

	// No sourceMappingURL found — if probing enabled, try common .map paths
	if probe {
		probeMapURL(scriptURL, &info)
	}

	return info
}

// probeMapURL tries appending .map to the script URL to see if a source map is accessible.
func probeMapURL(scriptURL string, info *ScriptInfo) {
	// Try scriptURL + ".map"
	candidates := []string{
		scriptURL + ".map",
	}

	// If URL has query params, try without them
	if parsed, err := url.Parse(scriptURL); err == nil && parsed.RawQuery != "" {
		clean := *parsed
		clean.RawQuery = ""
		candidates = append(candidates, clean.String()+".map")
	}

	for _, candidate := range candidates {
		mapBody, mapSize, err := fetchBodyWithSize(candidate)
		if err != nil {
			continue
		}
		// Verify it's actually a source map (not an error page)
		var sm sourceMapJSON
		if json.Unmarshal([]byte(mapBody), &sm) != nil {
			continue
		}
		if sm.Version == 0 && len(sm.Sources) == 0 {
			continue
		}

		info.HasMapRef = true
		info.MapURL = candidate
		info.MapAccessible = true
		info.MapSizeBytes = mapSize
		info.MapSizeHuman = humanSize(mapSize)
		info.SourcesCount = len(sm.Sources)
		info.Probed = true

		for _, sc := range sm.SourcesContent {
			if strings.TrimSpace(sc) != "" {
				info.HasSourceContent = true
				info.LinesExposed += strings.Count(sc, "\n") + 1
			}
		}
		return // Found one, stop probing
	}
}

// tryFetchMap attempts to download a map URL and populate info fields.
func tryFetchMap(mapFullURL string, info *ScriptInfo) {
	mapBody, mapSize, err := fetchBodyWithSize(mapFullURL)
	if err != nil {
		return
	}

	info.MapAccessible = true
	info.MapSizeBytes = mapSize
	info.MapSizeHuman = humanSize(mapSize)

	var sm sourceMapJSON
	if json.Unmarshal([]byte(mapBody), &sm) == nil {
		info.SourcesCount = len(sm.Sources)
		for _, sc := range sm.SourcesContent {
			if strings.TrimSpace(sc) != "" {
				info.HasSourceContent = true
				info.LinesExposed += strings.Count(sc, "\n") + 1
			}
		}
	}
}

func resolveMapURL(mapRef, scriptURL string, baseURL *url.URL) string {
	// If it's an absolute URL, use it directly
	if strings.HasPrefix(mapRef, "http://") || strings.HasPrefix(mapRef, "https://") {
		return mapRef
	}
	// Resolve relative to the script URL
	scriptParsed, err := url.Parse(scriptURL)
	if err != nil {
		return ""
	}
	refParsed, err := url.Parse(mapRef)
	if err != nil {
		return ""
	}
	return scriptParsed.ResolveReference(refParsed).String()
}

func fetchBody(rawURL string) (string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "srcleaks/1.0 (source map scanner)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100<<20)) // 100MB limit
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func fetchBodyWithSize(rawURL string) (string, int64, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "srcleaks/1.0 (source map scanner)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100<<20))
	if err != nil {
		return "", 0, err
	}
	return string(body), int64(len(body)), nil
}

func fetchSourceMapHeader(scriptURL string) string {
	req, err := http.NewRequest("HEAD", scriptURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "srcleaks/1.0 (source map scanner)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()

	// Check for SourceMap or X-SourceMap header
	if sm := resp.Header.Get("SourceMap"); sm != "" {
		return sm
	}
	if sm := resp.Header.Get("X-SourceMap"); sm != "" {
		return sm
	}
	return ""
}
