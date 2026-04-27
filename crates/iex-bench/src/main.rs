use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use iex_core::{
    prepare_search_targets, run_search_prepared, ExpressionPlan, PreparedSearchOptions,
    SearchConfig,
};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "iex-bench", about = "Loop benchmark helper for iEx")]
struct BenchArgs {
    #[arg(help = "Expression used for each benchmark iteration")]
    expr: String,

    #[arg(
        value_name = "PATH",
        num_args = 0..,
        default_value = ".",
        help = "One or more files or directories to scan"
    )]
    paths: Vec<PathBuf>,

    #[arg(long, default_value_t = 3)]
    warmup: usize,

    #[arg(long, default_value_t = 10)]
    loops: usize,

    #[arg(short, long)]
    threads: Option<usize>,
}

#[derive(Debug, Serialize)]
struct BenchSummary {
    scenario: BenchScenario,
    expression: String,
    loops: usize,
    warmup: usize,
    min_ms: f64,
    mean_ms: f64,
    p95_ms: f64,
    max_ms: f64,
    runs_ms: Vec<f64>,
}

#[derive(Debug, Serialize)]
struct BenchScenario {
    id: &'static str,
    intent: &'static str,
    discovery_contract: &'static str,
    execution_mode: &'static str,
    prepared_targets: bool,
    prepared_setup_ms: f64,
    file_count: usize,
    max_path_depth: usize,
    lazy_path_index_enabled: bool,
}

fn main() -> Result<()> {
    let args = BenchArgs::parse();
    let plan = ExpressionPlan::parse(&args.expr)?;
    let prepared_started = std::time::Instant::now();
    let prepared_targets = prepare_search_targets(
        args.paths.clone(),
        PreparedSearchOptions {
            include_hidden: false,
            follow_symlinks: false,
        },
    )?;
    let prepared_setup_ms = prepared_started.elapsed().as_secs_f64() * 1_000.0;
    let scenario = BenchScenario {
        id: "prepared_corpus_replay",
        intent: "Replay the same prepared corpus across warmup and measured loops without repaying discovery.",
        discovery_contract: "Discovery and root normalization happen once before warmup; each measured loop reuses the prepared file set.",
        execution_mode: "materialized_prepared",
        prepared_targets: true,
        prepared_setup_ms,
        file_count: prepared_targets.file_count(),
        max_path_depth: prepared_targets.max_path_depth(),
        lazy_path_index_enabled: prepared_targets.lazy_path_index_enabled(),
    };
    let mut config = SearchConfig::from_roots(args.paths.clone(), plan);
    config.threads = args.threads;

    for _ in 0..args.warmup {
        run_search_prepared(&config, &prepared_targets)?;
    }

    let mut runs = Vec::with_capacity(args.loops);
    for _ in 0..args.loops {
        let report = run_search_prepared(&config, &prepared_targets)?;
        runs.push(report.stats.timings.total_ms);
    }

    let mut sorted = runs.clone();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let min_ms = *sorted.first().unwrap_or(&0.0);
    let max_ms = *sorted.last().unwrap_or(&0.0);
    let mean_ms = if sorted.is_empty() {
        0.0
    } else {
        sorted.iter().sum::<f64>() / sorted.len() as f64
    };
    let p95_idx = if sorted.is_empty() {
        0
    } else {
        ((sorted.len() as f64) * 0.95).floor() as usize
    };
    let p95_ms = sorted
        .get(p95_idx.min(sorted.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0.0);

    let summary = BenchSummary {
        scenario,
        expression: args.expr,
        loops: args.loops,
        warmup: args.warmup,
        min_ms,
        mean_ms,
        p95_ms,
        max_ms,
        runs_ms: runs,
    };

    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
