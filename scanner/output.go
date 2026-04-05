package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ANSI colors
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	cyan    = "\033[36m"
	white   = "\033[37m"
	boldRed = "\033[1;31m"
	boldGrn = "\033[1;32m"
	boldYlw = "\033[1;33m"
	boldCyn = "\033[1;36m"
)

func statusColor(status string) string {
	switch status {
	case "CRITICAL", "EXPOSED":
		return boldRed
	case "WARNING":
		return boldYlw
	case "CLEAN":
		return boldGrn
	default:
		return white
	}
}

func PrintResult(r *NpmResult, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
		return
	}

	fmt.Println()
	fmt.Printf("%s┌─ srcleaks npm scan%s\n", boldCyn, reset)
	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s│%s  Package:    %s%s%s\n", cyan, reset, bold, r.Package, reset)
	fmt.Printf("%s│%s  Version:    %s\n", cyan, reset, r.Version)
	fmt.Printf("%s│%s  Status:     %s%s%s\n", cyan, reset, statusColor(r.Status), r.Status, reset)
	fmt.Printf("%s│%s  Risk Score: %s%d/10%s\n", cyan, reset, statusColor(r.Status), r.RiskScore, reset)
	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s│%s  Files in package:  %d\n", cyan, reset, r.TotalFiles)
	fmt.Printf("%s│%s  .map files:        %d\n", cyan, reset, r.MapFileCount)
	fmt.Printf("%s│%s  Inline maps:       %d\n", cyan, reset, r.InlineMapCount)
	fmt.Printf("%s│%s  With source code:  %d\n", cyan, reset, r.EmbeddedSrcCount)

	if r.TotalLinesExposed > 0 {
		fmt.Printf("%s│%s  Lines exposed:     %s~%s%s\n", cyan, reset, boldRed, FormatNumber(r.TotalLinesExposed), reset)
		fmt.Printf("%s│%s  Source files:      %s%d%s\n", cyan, reset, boldRed, r.TotalSourceFiles, reset)
	}

	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s├─ Findings%s\n", boldCyn, reset)

	for _, f := range r.Findings {
		icon := green + "✓" + reset
		if r.Status != "CLEAN" {
			icon = red + "✗" + reset
		}
		fmt.Printf("%s│%s  %s %s\n", cyan, reset, icon, f)
	}

	if len(r.MapDetails) > 0 {
		fmt.Printf("%s│%s\n", cyan, reset)
		fmt.Printf("%s├─ Map Files%s\n", boldCyn, reset)
		for _, d := range r.MapDetails {
			fmt.Printf("%s│%s  %s%s%s  %s(%s)%s\n", cyan, reset, yellow, d.File, reset, dim, d.SizeHuman, reset)
			if d.ValidJSON {
				fmt.Printf("%s│%s    sources: %d", cyan, reset, d.SourcesCount)
				if d.HasSourcesContent {
					fmt.Printf("  %s⚠ sourcesContent present (%s lines)%s", red, FormatNumber(d.LinesExposed), reset)
				}
				fmt.Println()
				if len(d.SampleSources) > 0 {
					fmt.Printf("%s│%s    %spaths:%s ", cyan, reset, dim, reset)
					fmt.Printf("%s%s%s\n", dim, strings.Join(d.SampleSources, ", "), reset)
				}
			} else {
				fmt.Printf("%s│%s    %sinvalid JSON%s\n", cyan, reset, dim, reset)
			}
		}
	}

	// Proof section — show recovered source code
	printNpmProof(r)

	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s└─%s\n", cyan, reset)
	fmt.Println()
}

func printNpmProof(r *NpmResult) {
	// Collect all proof from all map details
	var allProof []SourcePreview
	for _, d := range r.MapDetails {
		allProof = append(allProof, d.Proof...)
	}
	if len(allProof) == 0 {
		return
	}

	// Show up to 3 proof snippets total
	limit := 3
	if len(allProof) < limit {
		limit = len(allProof)
	}

	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s├─ Proof — Recovered Source Code%s\n", boldCyn, reset)
	fmt.Printf("%s│%s\n", cyan, reset)

	for i := 0; i < limit; i++ {
		p := allProof[i]
		fmt.Printf("%s│%s  %s%s%s  %s(%d lines)%s\n", cyan, reset, yellow, p.Path, reset, dim, p.Lines, reset)
		for _, line := range p.Preview {
			// Truncate long lines
			display := line
			if len(display) > 90 {
				display = display[:87] + "..."
			}
			fmt.Printf("%s│%s    %s%s%s\n", cyan, reset, dim, display, reset)
		}
		if i < limit-1 {
			fmt.Printf("%s│%s\n", cyan, reset)
		}
	}
}

func PrintURLResult(r *URLResult, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
		return
	}

	fmt.Println()
	fmt.Printf("%s┌─ srcleaks url scan%s\n", boldCyn, reset)
	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s│%s  URL:       %s%s%s\n", cyan, reset, bold, r.URL, reset)
	fmt.Printf("%s│%s  Status:    %s%s%s\n", cyan, reset, statusColor(r.Status), r.Status, reset)
	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s│%s  Scripts found:     %d\n", cyan, reset, r.ScriptsFound)
	fmt.Printf("%s│%s  Scripts scanned:   %d\n", cyan, reset, r.ScriptsScanned)
	fmt.Printf("%s│%s  Maps exposed:      %d\n", cyan, reset, r.MapsExposed)

	if r.TotalLinesExposed > 0 {
		fmt.Printf("%s│%s  Lines exposed:     %s~%s%s\n", cyan, reset, boldRed, FormatNumber(r.TotalLinesExposed), reset)
		fmt.Printf("%s│%s  Source files:      %s%d%s\n", cyan, reset, boldRed, r.TotalSourceFiles, reset)
	}

	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s├─ Findings%s\n", boldCyn, reset)
	for _, f := range r.Findings {
		icon := green + "✓" + reset
		if r.Status != "CLEAN" {
			icon = red + "✗" + reset
		}
		fmt.Printf("%s│%s  %s %s\n", cyan, reset, icon, f)
	}

	// Show scripts with exposed maps
	exposed := []ScriptInfo{}
	for _, s := range r.Scripts {
		if s.MapAccessible || s.InlineMap {
			exposed = append(exposed, s)
		}
	}

	if len(exposed) > 0 {
		fmt.Printf("%s│%s\n", cyan, reset)
		fmt.Printf("%s├─ Exposed Source Maps%s\n", boldCyn, reset)
		for _, s := range exposed {
			fmt.Printf("%s│%s  %s%s%s\n", cyan, reset, yellow, s.URL, reset)
			if s.MapURL != "" {
				probeTag := ""
				if s.Probed {
					probeTag = fmt.Sprintf(" %s[probed]%s", yellow, reset)
				}
				fmt.Printf("%s│%s    map: %s  %s(%s)%s%s\n", cyan, reset, s.MapURL, dim, s.MapSizeHuman, reset, probeTag)
			}
			if s.InlineMap {
				fmt.Printf("%s│%s    %sinline base64 source map%s\n", cyan, reset, red, reset)
			}
			if s.HasSourceContent {
				fmt.Printf("%s│%s    %s⚠ sourcesContent present — %d sources, ~%s lines%s\n",
					cyan, reset, red, s.SourcesCount, FormatNumber(s.LinesExposed), reset)
			}
		}

		// Print proof from URL results
		printURLProof(exposed)
	}

	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s└─%s\n", cyan, reset)
	fmt.Println()
}

func printURLProof(scripts []ScriptInfo) {
	var allProof []SourcePreview
	for _, s := range scripts {
		allProof = append(allProof, s.Proof...)
	}
	if len(allProof) == 0 {
		return
	}

	limit := 3
	if len(allProof) < limit {
		limit = len(allProof)
	}

	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s├─ Proof — Recovered Source Code%s\n", boldCyn, reset)
	fmt.Printf("%s│%s\n", cyan, reset)

	for i := 0; i < limit; i++ {
		p := allProof[i]
		fmt.Printf("%s│%s  %s%s%s  %s(%d lines)%s\n", cyan, reset, yellow, p.Path, reset, dim, p.Lines, reset)
		for _, line := range p.Preview {
			display := line
			if len(display) > 90 {
				display = display[:87] + "..."
			}
			fmt.Printf("%s│%s    %s%s%s\n", cyan, reset, dim, display, reset)
		}
		if i < limit-1 {
			fmt.Printf("%s│%s\n", cyan, reset)
		}
	}
}
