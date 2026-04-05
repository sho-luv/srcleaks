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

	// Check if sourcesContent is populated
	for _, sc := range sm.SourcesContent {
		if strings.TrimSpace(sc) != "" {
			detail.HasSourcesContent = true
			detail.LinesExposed += strings.Count(sc, "\n") + 1
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
