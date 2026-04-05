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

# Mix and match
srcleaks https://example.com express ./package.json
```

No subcommands. No flags to remember. It runs everything automatically.

## What It Detects

### npm packages (`srcleaks <package-name>`)
- `.map` files shipped in the tarball
- Inline base64 source maps in JS files
- `sourcesContent` fields containing original source code
- Risk scoring (0-10) with CLEAN / WARNING / CRITICAL ratings

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

srcleaks exits with code 1 when findings exceed the threshold:

```bash
# Exit 1 if any source maps found (default)
srcleaks my-package

# Exit 1 only on WARNING or higher (risk >= 4)
srcleaks my-package --threshold 4

# JSON output for parsing
srcleaks my-package --json
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output results as JSON |
| `--threshold` | 1 | Minimum risk score to trigger exit code 1 |
| `-c, --concurrency` | 5 | Parallel npm package scans |

## Background

Source maps are debugging files that map compiled/minified code back to the original source. They're essential for development but should never ship to production. When they do, anyone can reconstruct your original source code.

This happened to Anthropic — twice — when a 59.8 MB `.map` file was included in their `@anthropic-ai/claude-code` npm package, exposing ~512,000 lines across ~1,900 files.

This isn't an Anthropic-only problem. Any project using TypeScript, Webpack, Vite, or any bundler can make this exact mistake. One missed `.npmignore` rule and your source is public.

## License

MIT
