package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/sho-luv/srcleaks/scanner"
	"github.com/spf13/cobra"
)

var (
	jsonOutput  bool
	showProof   bool
	failOn      string
	concurrency int
)

// ExitCode is set when findings are detected.
var ExitCode int

var rootCmd = &cobra.Command{
	Use:   "srcleaks <target> [target...]",
	Short: "Scan for leaked source maps in npm packages, websites, and projects",
	Long: `srcleaks detects accidentally shipped source maps that expose original source code.

Just give it a target — it figures out the rest:

  srcleaks https://example.com          Scan a live website (JS files, probing, headers)
  srcleaks express lodash rxjs          Scan npm packages
  srcleaks ./package.json               Scan all dependencies + devDependencies
  srcleaks .                            Find package.json in current dir and scan it
  srcleaks https://example.com express  Mix and match — scan everything

All checks run automatically. No flags needed.

Statuses:
  EXPOSED  Source code is recoverable (sourcesContent present)
  LEAK     .map files found but no source code (reveals paths/structure)
  CLEAN    Nothing found`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAll(args)
	},
}

func init() {
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.Flags().BoolVar(&showProof, "proof", false, "Show recovered source code as verification")
	rootCmd.Flags().StringVar(&failOn, "fail-on", "exposed", "Exit 1 when status matches: exposed or leak")
	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 5, "Parallel npm package scans")
}

func Execute() error {
	return rootCmd.Execute()
}

// targetKind classifies what the user gave us.
type targetKind int

const (
	kindURL     targetKind = iota
	kindNpm
	kindBatch   // package.json or directory containing one
	kindList    // text file with one target per line
)

func classify(target string) targetKind {
	// URL?
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return kindURL
	}
	if u, err := url.Parse(target); err == nil && u.Host != "" && strings.Contains(u.Host, ".") {
		return kindURL
	}

	// File or directory on disk?
	info, err := os.Stat(target)
	if err == nil {
		if info.IsDir() {
			// Check for package.json inside
			pj := filepath.Join(target, "package.json")
			if _, err := os.Stat(pj); err == nil {
				return kindBatch
			}
		} else if strings.HasSuffix(target, "package.json") || strings.HasSuffix(target, ".json") {
			return kindBatch
		} else if info.Mode().IsRegular() {
			// Any other regular file — treat as a target list (one per line)
			return kindList
		}
	}

	// Default: treat as npm package name
	return kindNpm
}

// readTargetList reads a file with one target per line, skipping blank lines and comments.
func readTargetList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets, nil
}

func runAll(args []string) error {
	var urls []string
	var npms []string
	var batches []string

	// Expand all args, including target list files
	var expanded []string
	for _, arg := range args {
		if classify(arg) == kindList {
			targets, err := readTargetList(arg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s✗ %s: %v%s\n", red, arg, err, reset)
				continue
			}
			expanded = append(expanded, targets...)
		} else {
			expanded = append(expanded, arg)
		}
	}

	for _, arg := range expanded {
		switch classify(arg) {
		case kindURL:
			urls = append(urls, arg)
		case kindBatch:
			info, _ := os.Stat(arg)
			if info != nil && info.IsDir() {
				batches = append(batches, filepath.Join(arg, "package.json"))
			} else {
				batches = append(batches, arg)
			}
		case kindNpm:
			npms = append(npms, arg)
		}
	}

	hadFindings := false

	// 1. URL scans
	for _, u := range urls {
		fmt.Printf("%sScanning %s...%s\n", dim, u, reset)
		result, err := scanner.ScanURL(u, true) // always probe
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s✗ %s: %v%s\n", red, u, err, reset)
			continue
		}
		scanner.PrintURLResult(result, jsonOutput, showProof)
		if result.MapsExposed > 0 {
			hadFindings = true
		}
	}

	// 2. Batch scans (package.json) — collect all deps, dedupe, scan once
	allDeps := make(map[string]string)
	for _, pjPath := range batches {
		deps, err := readPackageJSON(pjPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s✗ %s: %v%s\n", red, pjPath, err, reset)
			continue
		}
		for k, v := range deps {
			allDeps[k] = v
		}
	}

	// 3. Add any explicit npm args
	for _, pkg := range npms {
		allDeps[pkg] = ""
	}

	// 4. Scan all npm packages
	if len(allDeps) > 0 {
		results := scanNpmBatch(allDeps)
		printBatchResults(results, jsonOutput)
		for _, r := range results {
			if r.Result != nil && shouldFail(r.Result.Status) {
				hadFindings = true
			}
		}
		// Only print full per-package details when --proof is requested
		if !jsonOutput && showProof {
			for _, r := range results {
				if r.Result != nil && r.Result.Status != "CLEAN" {
					scanner.PrintResult(r.Result, false, showProof)
				}
			}
		}
	}

	if hadFindings {
		ExitCode = 1
	}
	return nil
}

func readPackageJSON(pjPath string) (map[string]string, error) {
	data, err := os.ReadFile(pjPath)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	deps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		deps[k] = v
	}
	// Always include devDependencies
	for k, v := range pkg.DevDependencies {
		deps[k] = v
	}
	return deps, nil
}

type batchEntry struct {
	Name    string             `json:"name"`
	Version string             `json:"version"`
	Result  *scanner.NpmResult `json:"result,omitempty"`
	Error   string             `json:"error,omitempty"`
}

func scanNpmBatch(deps map[string]string) []batchEntry {
	type depSpec struct{ name, version string }
	var specs []depSpec
	for name, ver := range deps {
		specs = append(specs, depSpec{name, ver})
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].name < specs[j].name })

	fmt.Printf("\n%s┌─ Scanning %d npm packages%s\n%s│%s\n", boldCyn, len(specs), reset, cyan, reset)

	results := make([]batchEntry, len(specs))
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i, s := range specs {
		wg.Add(1)
		go func(idx int, spec depSpec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			entry := batchEntry{Name: spec.name, Version: spec.version}
			result, err := scanner.ScanNpmPackage(spec.name)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				entry.Error = err.Error()
				fmt.Printf("%s│%s  %s✗%s %-35s %serror: %s%s\n",
					cyan, reset, red, reset, spec.name, dim, err.Error(), reset)
			} else {
				entry.Result = result
				statusClr := statusColor(result.Status)
				icon := green + "✓" + reset
				extra := ""
				switch result.Status {
				case "EXPOSED":
					icon = red + "✗" + reset
					extra = fmt.Sprintf("  ~%s lines recoverable",
						scanner.FormatNumber(result.TotalLinesExposed))
					if result.IsPublicRepo {
						extra += fmt.Sprintf("  %s(open source)%s", dim, reset)
					}
				case "LEAK":
					icon = yellow + "!" + reset
					maps := result.MapFileCount + result.InlineMapCount
					extra = fmt.Sprintf("  %d .map file(s)", maps)
					if result.IsPublicRepo {
						extra += fmt.Sprintf("  %s(open source)%s", dim, reset)
					}
				}
				fmt.Printf("%s│%s  %s %-35s %s%-8s%s%s\n",
					cyan, reset, icon, spec.name, statusClr, result.Status, reset, extra)
			}
			results[idx] = entry
		}(i, s)
	}

	wg.Wait()
	return results
}

// ANSI
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	boldRed = "\033[1;31m"
	boldGrn = "\033[1;32m"
	boldYlw = "\033[1;33m"
	boldCyn = "\033[1;36m"
	cyan    = "\033[36m"
)

func statusColor(status string) string {
	switch status {
	case "EXPOSED":
		return boldRed
	case "LEAK":
		return boldYlw
	case "CLEAN":
		return boldGrn
	default:
		return reset
	}
}

// shouldFail returns true if the status warrants a non-zero exit code
// based on the --fail-on flag.
func shouldFail(status string) bool {
	switch failOn {
	case "leak":
		return status == "EXPOSED" || status == "LEAK"
	default: // "exposed"
		return status == "EXPOSED"
	}
}

func printBatchResults(results []batchEntry, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
		return
	}

	var clean, leak, exposed, errCount int
	for _, r := range results {
		if r.Error != "" {
			errCount++
			continue
		}
		switch r.Result.Status {
		case "CLEAN":
			clean++
		case "LEAK":
			leak++
		case "EXPOSED":
			exposed++
		}
	}

	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s├─ Summary%s\n", boldCyn, reset)
	fmt.Printf("%s│%s  Scanned:  %d\n", cyan, reset, len(results))
	fmt.Printf("%s│%s  %s✓ Clean:   %d%s\n", cyan, reset, boldGrn, clean, reset)
	if leak > 0 {
		fmt.Printf("%s│%s  %s⚠ Leak:    %d%s  %s(.map files, no source code)%s\n", cyan, reset, boldYlw, leak, reset, dim, reset)
	}
	if exposed > 0 {
		fmt.Printf("%s│%s  %s✗ Exposed: %d%s  %s(source code recoverable)%s\n", cyan, reset, boldRed, exposed, reset, dim, reset)
	}
	if errCount > 0 {
		fmt.Printf("%s│%s  %s? Errors:  %d%s\n", cyan, reset, dim, errCount, reset)
	}
	fmt.Printf("%s│%s\n", cyan, reset)
	fmt.Printf("%s└─%s\n\n", cyan, reset)
}
