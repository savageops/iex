# iEx Engine v2

iEx is a Rust search engine and benchmark platform for line-oriented text and code search.
It is built around a small expression language, an inspectable planner, and an evidence-first optimization loop.
The goal is not to be "another grep wrapper." The goal is to make search behavior, search cost, and benchmark truth explicit enough to improve the engine like an engine.

Canonical repo: [github.com/savageops/iEx](https://github.com/savageops/iEx)  
Canonical site: [iex.run](https://iex.run)

## What iEx Is Trying To Do

Most command-line search tools start from one pattern and a bag of flags.
iEx starts from a query plan.

Today, that plan is intentionally small:

- line-oriented matching over files and directories
- boolean composition with `&&` and `||`
- explicit predicate kinds for literals, prefixes, suffixes, and regex
- a separate `explain` command that shows how the query was parsed
- per-phase timings and slow-file telemetry on every search report

That narrower surface is deliberate.
It gives the repo room to optimize real execution paths instead of hiding complexity behind a large CLI surface too early.

## Project Status

iEx is an active performance project with a hard competitive target:
reach ripgrep-class performance and track progress toward at least `50%` faster than ripgrep on agreed workloads.

That target is real, but this README is not the source of truth for whether the target is currently met.
Benchmark truth lives in the latest generated artifacts under `tools/reports/` and in the live dashboard loop, not in static prose.

## Why This Repo Exists

This repository is the working loop for four things that usually drift apart:

1. the search engine itself
2. the public CLI surface
3. the benchmark and candidate-comparison harness
4. the operator documentation needed to keep speed claims honest

That is why the repo contains Rust crates, JavaScript benchmark scripts, a dashboard, reference clones, and planning-spec chains in one place.

## Current Command Surface

The public CLI is intentionally small:

- `search`: run a search over one or more files or directories
- `explain`: parse an expression and print the resulting plan as JSON

Current help output:

```text
Usage: iex-cli.exe <COMMAND>

Commands:
  search
  explain
  help
```

The narrow command surface is a feature, not a gap.
The repo is focused on the core search path first: parse well, execute well, measure well.

## Query Language

iEx expressions are built from explicit predicate tokens:

| Predicate | Meaning | Example |
| --- | --- | --- |
| `lit:` | raw substring match | `lit:error` |
| `prefix:` | line starts with the value | `prefix:WARN` |
| `suffix:` | line ends with the value | `suffix:Exception` |
| `re:` | regex match | `re:\btimeout\b` |

Boolean composition is currently simple and explicit:

- `A && B` means all predicates must match the same line
- `A || B` means any predicate may match the line
- a single expression is either one `&&` chain, one `||` chain, or one predicate
- nested grouping is not part of the current grammar

That last point matters.
iEx is not pretending to expose a full query language yet.
It exposes the planner surface the current engine can execute and benchmark cleanly.

### Examples

Search for lines that contain both a literal and a regex hit:

```powershell
cargo run -q -p iex-cli -- search "lit:error && re:\btimeout\b" logs --json
```

Search multiple roots in one command:

```powershell
cargo run -q -p iex-cli -- search "re:(ERR_SYS|PME_TURN_OFF|LINK_REQ_RST|CFG_BME_EVT)" .refs\ripgrep\benchsuite\linux src
```

Inspect the parsed plan:

```powershell
cargo run -q -p iex-cli -- explain "lit:error && re:\btimeout\b"
```

Example `explain` output:

```json
{"source":"lit:error && re:\\btimeout\\b","mode":"all","predicates":[{"type":"literal","value":"error"},{"type":"regex","value":"\\btimeout\\b"}]}
```

## Search Semantics

iEx is line-oriented today.
Matches are reported with:

- file path
- line number
- column
- preview text

When `--stats-only` is used, iEx stops collecting hit previews and returns counts plus telemetry.
That is the mode the benchmark harness relies on most heavily, because it isolates search-core behavior from output volume.

## How A Search Runs

At a high level, the engine does this:

1. parse the query into an `ExpressionPlan`
2. partition inputs into direct-file roots and directory roots
3. normalize and dedupe overlapping roots before scan ownership is assigned
4. choose the execution path
5. scan files, collect hits or counts, and emit timings

The important part is step 4.
iEx does not have one monolithic scan loop for every workload shape.
It has a small number of explicit paths chosen by input shape and output mode.

### Root Handling

`search` accepts one or more `PATH` arguments.
Those roots can be:

- files
- directories
- a mix of both

Directory roots share one discovery surface.
Direct-file roots stay on the direct-target path.
Overlaps and repeats are pruned before scan so mixed invocations do not silently double-count work.

### Discovery

Directory discovery is ignore-aware by default.
The engine uses the standard ignore stack:

- `.gitignore`
- global git excludes
- ignore files handled by the `ignore` crate stack

Hidden files stay off unless `--hidden` is enabled.
Symlink traversal stays off unless `--follow-symlinks` is enabled.

### File Reading Strategy

The engine does not read every file the same way.

- tiny files are read directly into a fixed inline buffer
- small files are loaded into memory
- larger files are memory-mapped
- likely binary files are rejected early by a null-byte sniff

That is an engine choice, not a README flourish.
The scan path is already shaped around different I/O costs.

### Matching Strategy

The planner and engine cooperate on a few key fast paths:

- literal matching uses byte-native finders
- regex predicates may collapse to faster literal-like paths when the regex shape allows it
- alternates can use automaton-backed paths
- `--stats-only` can take byte-count fast paths instead of full hit collection
- very large direct-file stats-only workloads can split safe byte ranges across cores

Recent engine work also widened compound `All` plans so queries such as `lit:A && lit:B` can take a reject-first byte path instead of always falling back to the slowest line loop.

### Streaming Stats-Only Path

There is a distinct streaming path for stats-only scans over multi-root directory workloads.
That path exists so discovery and scan work do not have to be fully serialized before counting begins.

This matters for telemetry interpretation:

- `discover_ms`
- `scan_ms`
- `aggregate_ms`
- `total_ms`

These are real phase measurements, but on streaming paths `discover_ms` and `scan_ms` can overlap instead of behaving like simple additive buckets.

## Output Model

`search` can emit either a readable summary or JSON.

Core report fields include:

- query expression
- hit list when hit collection is enabled
- files discovered
- files scanned
- files skipped
- matches found
- bytes scanned
- per-phase timings
- slowest-file telemetry

That report shape is not just for users.
It is also the metric contract used by the benchmark harness and the dashboard.

## Repository Layout

| Path | Responsibility |
| --- | --- |
| `crates/iex-core` | planner, discovery, scan engine, telemetry |
| `crates/iex-cli` | CLI contract for `search` and `explain` |
| `crates/iex-bench` | Rust-side benchmark helper binary |
| `tests/materialized` | explicit Vitest suites for contracts and benchmark tooling |
| `tools/scripts` | fixtures, benchmark runners, compare tools, installer scripts |
| `dashboard` | live benchmark dashboard |
| `.refs/ripgrep` | local upstream reference clone |
| `.refs/ugrep` | local contender reference clone |
| `.docs/iex-v2-crown-jewel.md` | deeper execution and benchmark doctrine |
| `todo/pending` | active planning-spec chains |

## Build And Run

### Basic local build

```powershell
cargo build -p iex-cli
```

### CLI help

```powershell
cargo run -q -p iex-cli -- --help
cargo run -q -p iex-cli -- search --help
```

### First searches

```powershell
cargo run -q -p iex-cli -- search "lit:Sherlock Holmes" .refs\ripgrep\benchsuite\subtitles\en.sample.txt
cargo run -q -p iex-cli -- search "lit:error && re:\btimeout\b" . --json --stats-only
cargo run -q -p iex-cli -- explain "lit:error && re:\btimeout\b"
```

### Contributor loop

```powershell
npm install
npm run fixtures
npm run test
```

## Native Install

For day-to-day operator use, iEx should be installed as a native command instead of run only through `cargo`.

### Windows

```powershell
npm run install:native:windows
```

The Windows installer:

- builds `target/release/iex-cli.exe` when needed
- snapshots the current release binary before replacing it
- installs the native command to `%LOCALAPPDATA%\Programs\iEx\bin\iex.exe`
- updates the user `PATH`
- remaps PowerShell's built-in `iex` alias so `iex` resolves to the installed binary in new sessions

`iex.exe` remains directly callable even if a shell session has not reloaded yet.

### macOS / Linux

```bash
npm run install:native:unix
```

The Unix installer:

- builds `target/release/iex-cli` when needed
- snapshots the current release binary before replacing it
- installs the binary to `~/.local/bin/iex`
- ensures `~/.local/bin` is exported in common shell profiles

Cross-platform dispatcher:

```bash
npm run install:native
```

## Benchmarking, Not Benchmark Theater

Search projects become unserious the moment performance claims detach from reproducible workloads.
This repo is set up specifically to stop that drift.

### Canonical benchmark surfaces

The repo keeps benchmark work split into canonical and diagnostic layers.

Canonical:

- `npm run bench:suite:list`
- `npm run bench:suite:download`
- `npm run bench:suite:bootstrap-data`
- `npm run bench:report`
- `npm run bench:loop`
- `npm run dashboard`

Diagnostic:

- `npm run bench:once`
- `npm run bench:report:diag`
- `npm run bench:contenders:direct`

The canonical suite is built around the ripgrep benchsuite corpora and current repo harnessing for:

- Linux source workloads
- English subtitles workloads
- Russian subtitles workloads
- literal, case-insensitive, word, alternates, surrounding-word, and no-literal regimes

### Benchmark truth policy

Three rules matter here:

1. static README claims do not override current artifacts
2. candidate binaries should be compared as immutable snapshots, not mutable `target/release` placeholders
3. live-loop promotion must clear a full-suite proof gate, not a cherry-picked one-profile win

That is why the benchmark scripts support `--iex-binary <path>`.
It lets the repo replay a frozen baseline or candidate without silently rebuilding the binary being measured.

Example pinned-binary replay:

```powershell
npm run bench:loop -- --loops 1 --iex-binary tools/reports/candidate-compare/iex-cli-baseline-YYYYMMDD-HHMMSS.exe
```

### Reports and telemetry

Key outputs:

- `tools/reports/live-metrics.jsonl`: append-only live loop history
- `tools/reports/latest.json`: latest live run snapshot
- `tools/reports/bench/`: benchsuite and diagnostic artifacts
- `tools/reports/candidate-compare/`: immutable binary snapshots and proof artifacts
- `.docs/bench/metrics-index.md`: human-readable metric interpretation

The dashboard and compare artifacts exist because serious search work needs more than one timing number.
You need to know whether the time moved in discovery, scan, aggregation, startup overhead, or one pathological file.

## Current Boundaries

This README is intentionally explicit about what iEx is not doing yet.

- it is not a full nested boolean query language
- it is not an indexed search engine
- it is not a multiline or archive-search engine
- it is not claiming permanent category leadership based on one screenshot or one run

The current engine is strongest when described as it actually exists:
a line-oriented, planner-driven, benchmark-heavy search engine under active optimization.

## Where To Read Next

If you want the deeper internal doctrine behind the repo:

- [`.docs/iex-v2-crown-jewel.md`](.docs/iex-v2-crown-jewel.md) for architecture, optimization waves, and live-loop promotion rules
- [`.docs/recon/ripgrep-harvest-2026-04-08.md`](.docs/recon/ripgrep-harvest-2026-04-08.md) for the current upstream-harvest map
- [`tools/scripts`](tools/scripts) for the benchmark and installation entrypoints
- [`crates/iex-core`](crates/iex-core) for the planner and scan engine

If you just want the shortest path to a real run:

```powershell
cargo run -q -p iex-cli -- search "lit:Sherlock Holmes" .refs\ripgrep\benchsuite\subtitles\en.sample.txt
```
