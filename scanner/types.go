package scanner

// NpmResult holds the full scan result for an npm package.
type NpmResult struct {
	Package         string      `json:"package"`
	Version         string      `json:"version"`
	TarballURL      string      `json:"tarball_url,omitempty"`
	Status          string      `json:"status"`
	RiskScore       int         `json:"risk_score"`
	TotalFiles      int         `json:"total_files"`
	MapFileCount    int         `json:"map_file_count"`
	InlineMapCount  int         `json:"inline_map_count"`
	EmbeddedSrcCount int        `json:"embedded_source_count"`
	TotalLinesExposed int       `json:"total_lines_exposed"`
	TotalSourceFiles  int       `json:"total_source_files"`
	Findings        []string    `json:"findings"`
	MapDetails      []MapDetail `json:"map_details,omitempty"`
}

// MapDetail describes a single .map file found in the package.
type MapDetail struct {
	File              string          `json:"file"`
	SizeBytes         int64           `json:"size_bytes"`
	SizeHuman         string          `json:"size_human"`
	ValidJSON         bool            `json:"valid_json"`
	SourcesCount      int             `json:"sources_count"`
	HasSourcesContent bool            `json:"has_sources_content"`
	LinesExposed      int             `json:"lines_exposed,omitempty"`
	SampleSources     []string        `json:"sample_sources,omitempty"`
	Proof             []SourcePreview `json:"proof,omitempty"`
}

// SourcePreview shows a snippet of recovered source code as proof.
type SourcePreview struct {
	Path    string   `json:"path"`
	Lines   int      `json:"lines"`
	Preview []string `json:"preview"`
}

// URLResult holds the scan result for a website URL.
type URLResult struct {
	URL            string       `json:"url"`
	Status         string       `json:"status"`
	ScriptsFound   int          `json:"scripts_found"`
	ScriptsScanned int          `json:"scripts_scanned"`
	MapsExposed    int          `json:"maps_exposed"`
	TotalLinesExposed int       `json:"total_lines_exposed"`
	TotalSourceFiles  int       `json:"total_source_files"`
	Findings       []string     `json:"findings"`
	Scripts        []ScriptInfo `json:"scripts,omitempty"`
}

// ScriptInfo describes a JS file found on the page and its source map status.
type ScriptInfo struct {
	URL              string `json:"url"`
	HasMapRef        bool   `json:"has_map_ref"`
	MapURL           string `json:"map_url,omitempty"`
	MapAccessible    bool   `json:"map_accessible"`
	MapSizeBytes     int64  `json:"map_size_bytes,omitempty"`
	MapSizeHuman     string `json:"map_size_human,omitempty"`
	SourcesCount     int    `json:"sources_count,omitempty"`
	HasSourceContent bool   `json:"has_source_content,omitempty"`
	LinesExposed     int    `json:"lines_exposed,omitempty"`
	InlineMap        bool            `json:"inline_map,omitempty"`
	Probed           bool            `json:"probed,omitempty"`
	SampleSources    []string        `json:"sample_sources,omitempty"`
	Proof            []SourcePreview `json:"proof,omitempty"`
}
