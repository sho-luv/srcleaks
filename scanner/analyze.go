package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	// //# sourceMappingURL=data:application/json;base64,...
	inlineMapRe = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*data:application/json;(?:charset=[^;]+;)?base64,(\S+)`)
	// //# sourceMappingURL=foo.js.map
	externalMapRe = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)\s*$`)
)

type sourceMapJSON struct {
	Version        int      `json:"version"`
	File           string   `json:"file"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
	Mappings       string   `json:"mappings"`
}

func analyzeMapFile(relPath string, data []byte) MapDetail {
	detail := MapDetail{
		File:      relPath,
		SizeBytes: int64(len(data)),
		SizeHuman: humanSize(int64(len(data))),
	}

	var sm sourceMapJSON
	if err := json.Unmarshal(data, &sm); err != nil {
		detail.ValidJSON = false
		return detail
	}

	detail.ValidJSON = true
	detail.SourcesCount = len(sm.Sources)

	// Check if sourcesContent is populated and extract proof
	proofCount := 0
	for i, sc := range sm.SourcesContent {
		if strings.TrimSpace(sc) == "" {
			continue
		}
		detail.HasSourcesContent = true
		lines := strings.Split(sc, "\n")
		detail.LinesExposed += len(lines)

		// Capture up to 3 proof snippets (first non-empty source files)
		if proofCount < 3 {
			path := ""
			if i < len(sm.Sources) {
				path = sm.Sources[i]
			}
			preview := extractPreviewLines(lines, 8)
			if len(preview) > 0 {
				detail.Proof = append(detail.Proof, SourcePreview{
					Path:    path,
					Lines:   len(lines),
					Preview: preview,
				})
				proofCount++
			}
		}
	}

	// Sample source paths
	limit := 8
	if len(sm.Sources) < limit {
		limit = len(sm.Sources)
	}
	detail.SampleSources = sm.Sources[:limit]

	return detail
}

// extractPreviewLines picks the first N non-empty lines from a source file.
func extractPreviewLines(lines []string, maxLines int) []string {
	var result []string
	for _, line := range lines {
		if len(result) >= maxLines {
			break
		}
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// SourceMapAnalysis holds the full analysis of a source map.
type SourceMapAnalysis struct {
	TotalSources  int
	SampleSources []string
	Proof         []SourcePreview
	LinesExposed  int
}

// AnalyzeSourceMap parses raw source map JSON and returns proof data.
// Used by the web scanner when it fetches a map.
func AnalyzeSourceMap(data []byte) *SourceMapAnalysis {
	var sm sourceMapJSON
	if json.Unmarshal(data, &sm) != nil {
		return nil
	}

	result := &SourceMapAnalysis{
		TotalSources: len(sm.Sources),
	}

	proofCount := 0
	for i, sc := range sm.SourcesContent {
		if strings.TrimSpace(sc) == "" {
			continue
		}
		lines := strings.Split(sc, "\n")
		result.LinesExposed += len(lines)

		if proofCount < 3 {
			path := ""
			if i < len(sm.Sources) {
				path = sm.Sources[i]
			}
			preview := extractPreviewLines(lines, 8)
			if len(preview) > 0 {
				result.Proof = append(result.Proof, SourcePreview{
					Path:    path,
					Lines:   len(lines),
					Preview: preview,
				})
				proofCount++
			}
		}
	}

	limit := 8
	if len(sm.Sources) < limit {
		limit = len(sm.Sources)
	}
	result.SampleSources = sm.Sources[:limit]
	return result
}

func extractInlineSourceMap(jsContent string) []byte {
	matches := inlineMapRe.FindStringSubmatch(jsContent)
	if len(matches) < 2 {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		// Try with padding stripped
		decoded, err = base64.RawStdEncoding.DecodeString(matches[1])
		if err != nil {
			return nil
		}
	}
	return decoded
}

// ExtractExternalMapRef returns the sourceMappingURL reference from a JS file.
func ExtractExternalMapRef(jsContent string) string {
	matches := externalMapRe.FindStringSubmatch(jsContent)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func humanSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
