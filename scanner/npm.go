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
	name, version, tarballURL, err := resolvePackage(spec)
	if err != nil {
		return nil, fmt.Errorf("resolving package: %w", err)
	}

	result := &NpmResult{
		Package:    name,
		Version:    version,
		TarballURL: tarballURL,
	}

	// Download tarball
	resp, err := http.Get(tarballURL)
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

	// Score
	result.RiskScore = scoreNpm(result)
	result.Status = statusFromScore(result.RiskScore)
	result.Findings = buildFindings(result)

	return result, nil
}

func resolvePackage(spec string) (name, version, tarballURL string, err error) {
	// Parse spec like "@scope/pkg@1.0.0" or "pkg" or "pkg@latest"
	registryURL := "https://registry.npmjs.org/"

	// Split name and version
	atIdx := strings.LastIndex(spec, "@")
	if atIdx > 0 { // not the first char (scoped packages start with @)
		name = spec[:atIdx]
		version = spec[atIdx+1:]
	} else {
		name = spec
		version = "latest"
	}

	// Fetch package metadata
	metaURL := registryURL + name
	if version != "latest" {
		metaURL = registryURL + name + "/" + version
	}

	resp, err := http.Get(metaURL)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return "", "", "", fmt.Errorf("package %q not found on npm", spec)
	}
	if resp.StatusCode != 200 {
		return "", "", "", fmt.Errorf("npm registry returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", err
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", "", "", err
	}

	// If we got a specific version doc, extract directly
	if dist, ok := meta["dist"].(map[string]interface{}); ok {
		tarballURL, _ = dist["tarball"].(string)
		v, _ := meta["version"].(string)
		return name, v, tarballURL, nil
	}

	// Otherwise we got the full package doc — resolve "latest" or dist-tag
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
		return "", "", "", fmt.Errorf("could not parse versions from npm response")
	}

	vData, ok := versions[version].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("version %q not found for %s", version, name)
	}

	dist, _ := vData["dist"].(map[string]interface{})
	if dist != nil {
		tarballURL, _ = dist["tarball"].(string)
	}

	return name, version, tarballURL, nil
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

func scoreNpm(r *NpmResult) int {
	score := 0
	if r.MapFileCount > 0 {
		score += 3
	}
	if r.MapFileCount > 5 {
		score += 1
	}
	if r.InlineMapCount > 0 {
		score += 2
	}
	if r.EmbeddedSrcCount > 0 {
		score += 3
	}
	if r.TotalLinesExposed > 10000 {
		score += 1
	}
	if score > 10 {
		score = 10
	}
	return score
}

func statusFromScore(score int) string {
	if score >= 7 {
		return "CRITICAL"
	}
	if score >= 4 {
		return "WARNING"
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
