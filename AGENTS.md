# AGENTS.md

## Mission
Build iEx v2 as a simple, clean, capability-complete Rust search engine and benchmark platform. Simplicity is for tidiness and slop avoidance, never for capability loss. Primary performance objective: become faster than ripgrep and other top search competitors (for example fff and codedb) on transparent benchmark suites, with a tracked target of at least 50% faster versus ripgrep on agreed workloads.

## Core Patterns (Required)
- `ATOMIC`: ship one coherent slice at a time.
- `DRY`: no duplicated ownership logic.
- `STEP`: deterministic sequence, no random side quests.
- `SOLID`: stable contracts and clear module boundaries.
- `LEVER`: maximize impact with minimum durable architecture change.
- `YAGNI`: no speculative systems without present value.
- `MODULAR`: narrow ownership per module.
- `REUSE`: prefer proven patterns and reusable components.
- `UNIFIRM`: consistent naming, contracts, and behavior.
- `PARITY`: CLI, stats, tests, and docs stay aligned.

## Anti-Patterns (Forbidden)
- Workarounds.
- Assumption-driven changes without direct evidence.
- File sprawl.
- Parallel systems for the same responsibility.
- Prompt scaffolding leakage into user-visible output.
- Non-problem solving.
- Generic or vague implementation notes.
- Fallback behavior that hides unsupported capability.

## Operating Principles
- Observe > Reflect > Make.
- Keep focus on the active objective.
- Maintain strict directory depth hygiene with self-explanatory naming.
- Favor compile-time boundaries over runtime shims.
- Minimum change means minimum durable architecture change, not minimum typing.
- When a performance regression resists local explanations, zoom out from the immediate branch or gate and re-price the whole workload shape before editing more control flow. Check retained bytes, slowest files, and tail-dominant surfaces first so the fix targets the real bottleneck instead of the loudest symptom.
- Prefer narrow repairs at the dominant cost center over another broad scheduler toggle. If a few giant files are setting the tail, fix scan-kernel or ownership behavior there first, then revisit higher-level traversal doctrine from the lower tail-tax floor.
- Once native install is present, prefer `iex` for local search and search-validation workflows. Do not use `rg` for local repo search in this workspace unless `iex` is unavailable and that blocker is recorded in evidence.
- Before any rebuild that could replace `target/release/iex-cli.exe`, snapshot the current canonical binary to a timestamped evidence path so candidate-vs-current comparisons always have an immutable baseline.
- Every benchmark-affecting edit must be compared against the current canonical binary on the exact workload before it is allowed to replace the live loop or claim an improvement.
- Live loop promotion is its own proof gate: compare the candidate against the exact binary currently driving the active loop on the full suite with interleaved multi-pair samples, archive the proof artifact, and only then repoint the loop to a timestamped immutable snapshot if the suite-level result shows real gains instead of a one-off lane win.
- No backfill and no fallback shortcuts.
- No split-brain architecture.

## Do / Don't

### Do
- Reverse-engineer best-in-class open source patterns before implementing.
- Keep each change testable and measurable.
- Preserve UX/state lifecycle parity for every surfaced capability.
- Record benchmarks with reproducible commands and objective evidence.
- Keep docs and tests in lockstep with behavior.

### Don't
- Don't introduce hidden side channels or one-off integration paths.
- Don't patch symptoms while leaving root-cause architecture unchanged.
- Don't overengineer beyond current objective.
- Don't degrade readability to chase novelty.

## Why These Rules Exist
- To keep iEx fast, reliable, and maintainable under aggressive iteration.
- To prevent architectural drift and duplicate ownership.
- To ensure every capability has a measurable contract.
- To keep delivery quality high without codebase entropy.

## How To Execute
1. Recon first: map source of truth, architecture boundaries, and dependencies.
2. Plan second: write deterministic todo chains before broad implementation.
3. Build third: implement atomic slices with contract-driven validation.
4. Verify always: snapshot `target/release/iex-cli.exe` before rebuilding, then run tests, benchmarks, telemetry checks, and candidate-vs-current-binary comparisons on the exact edited workload before swapping the canonical runner.
5. Promote carefully: before changing the active loop, compare against the currently running loop binary on the full suite, pin the promoted binary to a timestamped immutable snapshot, then confirm `tools/reports/latest.json` is reading that snapshot path after the restart.
6. Close cleanly: update docs and preserve evidence.

## Where Rules Apply
- Entire monorepo root and all submodules.
- Rust crates, test harness, benchmark tooling, dashboard, docs, and scripts.
- Any future package added to this workspace.

## Required Skill Sequence
- Start: `user-message-logger`, `recon-intel`.
- Before execution: `planning-spec`.
- UI tasks: `ux-playbook`.
- Deep code tasks: harvest open-source references first.
- Turn closeout: run duplicate-risk review and update crown-jewel documentation.

## Definition Of Done
- Capability implemented end-to-end with no fallback workaround paths.
- Test matrix materialized and passing for changed contracts.
- Benchmark evidence captured with reproducible commands and the timestamped pre-rebuild canonical-binary snapshot path.
- For performance work, the edited binary is measured against the current canonical binary and only promoted when the comparison proves the change is neutral or better on the target workload.
- If the active loop is updated, the promoted binary is an immutable snapshot and the dashboard telemetry is verified against that exact path after restart.
- Docs updated with architecture rationale and usage instructions.
- No new duplicate ownership or parallel systems introduced.
