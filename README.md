# srcleaks

Scan for leaked source maps in npm packages and live websites. One command, auto-detects what you give it, runs all checks.

Inspired by [Anthropic accidentally shipping 512,000 lines of Claude Code source via a `.map` file in their npm package](https://sholuv.net/blog/posts/anthropic-source-map-leak/).

![srcleaks demo](demo/srcleaks-demo.gif)

## Install

```bash
go install github.com/sho-luv/srcleaks@latest
```

Or build from source:

```bash
git clone https://github.com/sho-luv/srcleaks.git
cd srcleaks
go build -o srcleaks .
```

## Usage

Just give it a target. It figures out the rest.

```bash
# Scan npm packages
srcleaks express rxjs lodash

# Scan a live website (checks JS files, probes for .map files, checks headers)
srcleaks https://example.com

# Scan all deps + devDeps from a package.json
srcleaks ./package.json

# Point it at a directory — it finds the package.json
srcleaks .

# Scan a file with one target per line
srcleaks targets.txt

# Scan all packages from an npm org
srcleaks --org anthropic-ai
srcleaks --org openai --org google

# Mix and match
srcleaks https://example.com express ./package.json
```

No subcommands. No flags to remember. It runs everything automatically.

## Statuses

| Status | Meaning |
|--------|---------|
| **EXPOSED** | Source code is recoverable (`sourcesContent` present) |
| **LEAK** | `.map` files found but no source code (reveals paths/structure) |
| **CLEAN** | Nothing found |

Open source packages with source maps are automatically marked as CLEAN with a note — if the code is already public, shipping `.map` files is a packaging concern, not a security issue.

## What It Detects

### npm packages (`srcleaks <package-name>`)
- `.map` files shipped in the tarball
- Inline base64 source maps in JS files
- `sourcesContent` fields containing original source code
- Open source detection (checks if repo is public)

### Live websites (`srcleaks <url>`)
- `sourceMappingURL` comments in JS files
- `SourceMap` / `X-SourceMap` HTTP headers
- Inline base64 source maps
- Probes `.map` paths even without explicit references
- Fetches and analyzes any accessible map files

### Projects (`srcleaks <path>`)
- Reads `package.json` (dependencies + devDependencies)
- Scans all packages in parallel
- Summary with per-package status

## CI Usage

srcleaks exits with code 1 when findings are detected:

```bash
# Exit 1 on EXPOSED (default)
srcleaks my-package

# Exit 1 on EXPOSED or LEAK
srcleaks my-package --fail-on leak

# JSON output for parsing
srcleaks my-package --json

# Verify findings with recovered source code
srcleaks my-package --proof
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output results as JSON |
| `--proof` | false | Show recovered source code as verification |
| `--fail-on` | `exposed` | Exit 1 when status matches: `exposed` or `leak` |
| `--org` | | Scan all npm packages from an org (e.g. `anthropic-ai`) |
| `-c, --concurrency` | 5 | Parallel npm package scans |

## Finding Targets

These tools are useful for discovering packages to scan:

| Tool | What it does |
|------|-------------|
| [npmjs.com](https://www.npmjs.com) | Browse and search npm packages |
| [npmtrends.com](https://npmtrends.com) | Compare download trends across packages |
| [npm-stat.com](https://npm-stat.com) | Download charts and statistics over time |
| [socket.dev/npm/category/popular](https://socket.dev/npm/category/popular) | Top 250 most downloaded packages |

### npm Registry API

```bash
# Search for packages
curl -s "https://registry.npmjs.org/-/v1/search?text=<query>&size=10"

# Weekly download count
curl -s "https://api.npmjs.org/downloads/point/last-week/<package>"

# Bulk download stats (up to 128 packages)
curl -s "https://api.npmjs.org/downloads/point/last-week/react,express,lodash"

# Download history over a date range
curl -s "https://api.npmjs.org/downloads/range/2025-01-01:2025-12-31/<package>"
```

## Background

Source maps are debugging files that map compiled/minified code back to the original source. They're essential for development but should never ship to production. When they do, anyone can reconstruct your original source code.

This happened to Anthropic — twice — when a 59.8 MB `.map` file was included in their `@anthropic-ai/claude-code` npm package, exposing ~512,000 lines across ~1,900 files.

This isn't an Anthropic-only problem. Any project using TypeScript, Webpack, Vite, or any bundler can make this exact mistake. One missed `.npmignore` rule and your source is public.

## License

MIT
