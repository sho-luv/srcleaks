package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sho-luv/srcleaks/scanner"
	"github.com/spf13/cobra"
)

var (
	jsonOutput  bool
	showProof   bool
	failOn      string
	concurrency int
	orgs        []string
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
  srcleaks --org anthropic-ai           Scan all packages from an npm org
  srcleaks --org openai --org google    Multiple orgs at once

All checks run automatically. No flags needed.

Statuses:
  EXPOSED  Source code is recoverable (sourcesContent present)
  LEAK     .map files found but no source code (reveals paths/structure)
  CLEAN    Nothing found`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && len(orgs) == 0 {
			return fmt.Errorf("provide at least one target or use --org")
		}
		return runAll(args)
	},
}

func init() {
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.Flags().BoolVar(&showProof, "proof", false, "Show recovered source code as verification")
	rootCmd.Flags().StringVar(&failOn, "fail-on", "exposed", "Exit 1 when status matches: exposed or leak")
	rootCmd.Flags().StringArrayVar(&orgs, "org", nil, "Scan all npm packages from an org (e.g. anthropic-ai)")
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

	// Resolve --org flags into package names
	for _, org := range orgs {
		fmt.Printf("%sDiscovering packages for @%s...%s\n", dim, org, reset)
		pkgs, err := discoverOrgPackages(org)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s✗ @%s: %v%s\n", red, org, err, reset)
			continue
		}
		fmt.Printf("%sFound %d packages for @%s%s\n", dim, len(pkgs), org, reset)
		args = append(args, pkgs...)
	}

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
			if r.Result != nil && !r.Result.IsPublicRepo && shouldFail(r.Result.Status) {
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
				icon := green + "✓" + reset
				displayStatus := result.Status
				statusClr := statusColor(result.Status)
				extra := ""

				// Open source packages with source maps aren't real leaks
				if result.IsPublicRepo && result.Status != "CLEAN" {
					icon = dim + "·" + reset
					displayStatus = "CLEAN"
					statusClr = boldGrn
					maps := result.MapFileCount + result.InlineMapCount
					extra = fmt.Sprintf("  %s(open source, %d .map file(s) — not a leak)%s", dim, maps, reset)
				} else {
					switch result.Status {
					case "EXPOSED":
						icon = red + "✗" + reset
						extra = fmt.Sprintf("  ~%s lines recoverable",
							scanner.FormatNumber(result.TotalLinesExposed))
					case "LEAK":
						icon = yellow + "!" + reset
						maps := result.MapFileCount + result.InlineMapCount
						extra = fmt.Sprintf("  %d .map file(s)", maps)
					}
				}
				fmt.Printf("%s│%s  %s %-35s %s%-8s%s%s\n",
					cyan, reset, icon, spec.name, statusClr, displayStatus, reset, extra)
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

	var clean, leak, exposed, openSrc, errCount int
	for _, r := range results {
		if r.Error != "" {
			errCount++
			continue
		}
		if r.Result.IsPublicRepo && r.Result.Status != "CLEAN" {
			openSrc++
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
	fmt.Printf("%s│%s  %s✓ Clean:   %d%s\n", cyan, reset, boldGrn, clean+openSrc, reset)
	if openSrc > 0 {
		fmt.Printf("%s│%s    %s↳ %d open source (source maps shipped but not a risk)%s\n", cyan, reset, dim, openSrc, reset)
	}
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

// discoverOrgPackages queries the npm registry for all packages under a scope.
func discoverOrgPackages(org string) ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	scope := org
	if !strings.HasPrefix(scope, "@") {
		scope = "@" + scope
	}

	var allPkgs []string
	from := 0
	pageSize := 250
	emptyPages := 0 // consecutive pages with no matching packages

	for {
		orgName := strings.TrimPrefix(scope, "@")
		searchURL := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=scope:%s&size=%d&from=%d",
			orgName, pageSize, from)

		body, err := npmSearchFetch(client, searchURL)
		if err != nil {
			return nil, err
		}

		var result struct {
			Objects []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
			} `json:"objects"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("parsing npm search response: %w", err)
		}

		found := 0
		for _, obj := range result.Objects {
			name := obj.Package.Name
			// Only include packages that actually belong to this scope
			if strings.HasPrefix(name, scope+"/") {
				allPkgs = append(allPkgs, name)
				found++
			}
		}

		// npm search returns fuzzy matches ranked by relevance.
		// Stop after 2 consecutive pages with no scope matches.
		if found == 0 {
			emptyPages++
		} else {
			emptyPages = 0
		}

		from += pageSize
		if from >= result.Total || len(result.Objects) == 0 || emptyPages >= 2 {
			break
		}
	}

	if len(allPkgs) == 0 {
		return nil, fmt.Errorf("no packages found for scope %s", scope)
	}

	return allPkgs, nil
}

// npmSearchFetch fetches a URL with retry on 429 rate limits.
func npmSearchFetch(client *http.Client, rawURL string) ([]byte, error) {
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Encoding", "identity")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()
			wait := time.Duration(attempt+1) * 3 * time.Second
			fmt.Printf("%s  rate limited, retrying in %s...%s\n", dim, wait, reset)
			time.Sleep(wait)
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("npm search returned HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		return body, err
	}
	return nil, fmt.Errorf("npm search rate limited after retries")
}
