# iEx Engine

iEx (`intelligent expressions`) is a Rust-first search framework designed to evolve beyond linear regex workflows.

## Layout

- `crates/iex-core`: expression planner + high-throughput scanner
- `crates/iex-cli`: CLI binary surface
- `crates/iex-bench`: benchmark helper binary
- `tests`: Vitest suites (300+ materialized tests)
- `tools/scripts`: benchmark loop + report tooling
- `dashboard`: live HTML dashboard for loop telemetry
- `.refs/ripgrep`: upstream baseline reference clone
- `todo/pending`: planning-spec todo chain

## Quickstart

```powershell
cargo build -p iex-cli
npm install
npm run fixtures
npm run test
npm run bench:loop
npm run dashboard
```

## Benchmark telemetry

- One-shot run: `node tools/scripts/run-once-benchmark.mjs --build-profile release --warmup 1`
- Loop runner: `node tools/scripts/bench-loop.mjs --loops 1 --build-profile release --warmup 1`
- Live dashboard: `node tools/scripts/dashboard-server.mjs`
- Reports:
  - `tools/reports/live-metrics.jsonl` (append-only history)
  - `tools/reports/latest.json` (latest snapshot)
- Competitor commands are configured in `tools/scripts/competitors.json`.
- Metric model:
  - `iexMs`: iEx core engine time (`report.stats.timings.total_ms`)
  - `iexCliMs`: full CLI wall-clock time (startup + parse + engine + output)
  - `iexProcessOverheadMs`: `iexCliMs - iexMs`
  - `rgMs`: competitor CLI wall-clock time

## Ripgrep

- Reference clone: `.refs/ripgrep`

## Performance goal

The target is to iteratively optimize iEx until it beats ripgrep and other top search competitors (including fff and codedb where applicable) with a tracked goal of >= 50% faster than ripgrep on agreed benchmark suites.
