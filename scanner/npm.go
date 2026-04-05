package scanner

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ScanNpmPackage downloads and scans an npm package for source maps.
func ScanNpmPackage(spec string) (*NpmResult, error) {
	pkgInfo, err := resolvePackage(spec)
	if err != nil {
		return nil, fmt.Errorf("resolving package: %w", err)
	}

	result := &NpmResult{
		Package:    pkgInfo.Name,
		Version:    pkgInfo.Version,
		TarballURL: pkgInfo.TarballURL,
		License:    pkgInfo.License,
		RepoURL:    pkgInfo.RepoURL,
	}

	// Check if the repo is public
	if pkgInfo.RepoURL != "" {
		result.IsPublicRepo = isPublicRepo(pkgInfo.RepoURL)
	}

	// Download tarball
	resp, err := http.Get(pkgInfo.TarballURL)
	if err != nil {
		return nil, fmt.Errorf("downloading tarball: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("tarball returned HTTP %d", resp.StatusCode)
	}

	// Save to temp file
	tmpFile, err := os.CreateTemp("", "srcleaks-*.tgz")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return nil, err
	}
	tmpFile.Close()

	// Extract and scan
	if err := scanTarball(tmpFile.Name(), result); err != nil {
		return nil, fmt.Errorf("scanning tarball: %w", err)
	}

	// Status
	result.Status = classifyStatus(result)
	result.Findings = buildFindings(result)

	return result, nil
}

type packageInfo struct {
	Name       string
	Version    string
	TarballURL string
	License    string
	RepoURL    string
}

func resolvePackage(spec string) (*packageInfo, error) {
	registryURL := "https://registry.npmjs.org/"

	var name, version string
	atIdx := strings.LastIndex(spec, "@")
	if atIdx > 0 {
		name = spec[:atIdx]
		version = spec[atIdx+1:]
	} else {
		name = spec
		version = "latest"
	}

	metaURL := registryURL + name
	if version != "latest" {
		metaURL = registryURL + name + "/" + version
	}

	resp, err := http.Get(metaURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("package %q not found on npm", spec)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("npm registry returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, err
	}

	info := &packageInfo{Name: name}

	// Helper to extract repo/license from a version doc
	extractMeta := func(doc map[string]interface{}) {
		info.License = extractLicense(doc)
		info.RepoURL = extractRepoURL(doc)
	}

	// If we got a specific version doc, extract directly
	if dist, ok := meta["dist"].(map[string]interface{}); ok {
		info.TarballURL, _ = dist["tarball"].(string)
		info.Version, _ = meta["version"].(string)
		extractMeta(meta)
		return info, nil
	}

	// Full package doc — resolve version
	distTags, _ := meta["dist-tags"].(map[string]interface{})
	if distTags != nil {
		if version == "latest" {
			version, _ = distTags["latest"].(string)
		} else if resolved, ok := distTags[version].(string); ok {
			version = resolved
		}
	}

	versions, _ := meta["versions"].(map[string]interface{})
	if versions == nil {
		return nil, fmt.Errorf("could not parse versions from npm response")
	}

	vData, ok := versions[version].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("version %q not found for %s", version, name)
	}

	info.Version = version
	dist, _ := vData["dist"].(map[string]interface{})
	if dist != nil {
		info.TarballURL, _ = dist["tarball"].(string)
	}
	extractMeta(vData)

	// Fall back to top-level metadata for repo/license
	if info.RepoURL == "" {
		info.RepoURL = extractRepoURL(meta)
	}
	if info.License == "" {
		info.License = extractLicense(meta)
	}

	return info, nil
}

func extractLicense(doc map[string]interface{}) string {
	if l, ok := doc["license"].(string); ok {
		return l
	}
	return ""
}

func extractRepoURL(doc map[string]interface{}) string {
	repo, ok := doc["repository"]
	if !ok {
		return ""
	}
	// Can be a string or an object with "url" field
	if s, ok := repo.(string); ok {
		return normalizeRepoURL(s)
	}
	if obj, ok := repo.(map[string]interface{}); ok {
		if u, ok := obj["url"].(string); ok {
			return normalizeRepoURL(u)
		}
	}
	return ""
}

func normalizeRepoURL(raw string) string {
	// Convert git+https://github.com/foo/bar.git → https://github.com/foo/bar
	raw = strings.TrimPrefix(raw, "git+")
	raw = strings.TrimPrefix(raw, "git://")
	raw = strings.TrimSuffix(raw, ".git")
	if strings.HasPrefix(raw, "github:") {
		raw = "https://github.com/" + strings.TrimPrefix(raw, "github:")
	}
	if !strings.HasPrefix(raw, "http") && strings.Contains(raw, "github.com") {
		raw = "https://" + raw
	}
	return raw
}

func isPublicRepo(repoURL string) bool {
	if repoURL == "" {
		return false
	}
	req, err := http.NewRequest("HEAD", repoURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "srcleaks/1.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

func scanTarball(tgzPath string, result *NpmResult) error {
	f, err := os.Open(tgzPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var allFiles []string
	mapFiles := make(map[string][]byte) // rel path -> content
	jsFiles := make(map[string][]byte)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Strip leading "package/" prefix
		rel := hdr.Name
		if idx := strings.Index(rel, "/"); idx >= 0 {
			rel = rel[idx+1:]
		}
		allFiles = append(allFiles, rel)

		ext := strings.ToLower(filepath.Ext(rel))

		if ext == ".map" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			mapFiles[rel] = data
		} else if ext == ".js" || ext == ".mjs" || ext == ".cjs" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			jsFiles[rel] = data
		}
	}

	result.TotalFiles = len(allFiles)
	result.MapFileCount = len(mapFiles)

	// Analyze .map files
	for rel, data := range mapFiles {
		detail := analyzeMapFile(rel, data)
		result.MapDetails = append(result.MapDetails, detail)
		if detail.HasSourcesContent {
			result.EmbeddedSrcCount++
			result.TotalLinesExposed += detail.LinesExposed
			result.TotalSourceFiles += detail.SourcesCount
		}
	}

	// Check JS files for inline source maps
	for rel, data := range jsFiles {
		content := string(data)
		if inlineMap := extractInlineSourceMap(content); inlineMap != nil {
			result.InlineMapCount++
			detail := analyzeMapFile(rel+".inline", inlineMap)
			detail.File = rel + " (inline)"
			result.MapDetails = append(result.MapDetails, detail)
			if detail.HasSourcesContent {
				result.EmbeddedSrcCount++
				result.TotalLinesExposed += detail.LinesExposed
				result.TotalSourceFiles += detail.SourcesCount
			}
		}
	}

	return nil
}

// classifyStatus determines the status based on what was actually found.
//   EXPOSED — sourcesContent present, original source code is recoverable
//   LEAK    — .map files found but no sourcesContent (reveals paths/structure)
//   CLEAN   — nothing found
func classifyStatus(r *NpmResult) string {
	if r.EmbeddedSrcCount > 0 {
		return "EXPOSED"
	}
	if r.MapFileCount > 0 || r.InlineMapCount > 0 {
		return "LEAK"
	}
	return "CLEAN"
}

func buildFindings(r *NpmResult) []string {
	var findings []string
	if r.MapFileCount > 0 {
		findings = append(findings, fmt.Sprintf("%d .map file(s) shipped in package", r.MapFileCount))
	}
	if r.InlineMapCount > 0 {
		findings = append(findings, fmt.Sprintf("%d JS file(s) contain inline source maps", r.InlineMapCount))
	}
	if r.EmbeddedSrcCount > 0 {
		findings = append(findings, fmt.Sprintf("%d map(s) contain full sourcesContent — original source recoverable", r.EmbeddedSrcCount))
	}
	if r.TotalLinesExposed > 0 {
		findings = append(findings, fmt.Sprintf("~%s lines of source code exposed across %d files",
			FormatNumber(r.TotalLinesExposed), r.TotalSourceFiles))
	}
	// Context about whether the source is already public
	if r.Status != "CLEAN" {
		if r.IsPublicRepo {
			findings = append(findings, "Source repo is public — this is a packaging issue, not a proprietary code leak")
		} else if r.RepoURL != "" {
			findings = append(findings, "Source repo is private or inaccessible — this may be a proprietary code leak")
		} else {
			findings = append(findings, "No public repository found — source may be proprietary")
		}
	}
	if len(findings) == 0 {
		findings = append(findings, "No source maps found")
	}
	return findings
}

func FormatNumber(n int) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%dM", n/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%dk", n/1_000)
	}
	return fmt.Sprintf("%d", n)
}
