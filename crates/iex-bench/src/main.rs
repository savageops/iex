use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use iex_core::{run_search, ExpressionPlan, SearchConfig};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "iex-bench", about = "Loop benchmark helper for iEx")]
struct BenchArgs {
    #[arg(help = "Expression used for each benchmark iteration")]
    expr: String,

    #[arg(default_value = ".", help = "Path to scan")]
    path: PathBuf,

    #[arg(long, default_value_t = 3)]
    warmup: usize,

    #[arg(long, default_value_t = 10)]
    loops: usize,

    #[arg(short, long)]
    threads: Option<usize>,
}

#[derive(Debug, Serialize)]
struct BenchSummary {
    expression: String,
    loops: usize,
    warmup: usize,
    min_ms: f64,
    mean_ms: f64,
    p95_ms: f64,
    max_ms: f64,
    runs_ms: Vec<f64>,
}

fn main() -> Result<()> {
    let args = BenchArgs::parse();
    let plan = ExpressionPlan::parse(&args.expr)?;
    let mut config = SearchConfig::new(args.path.clone(), plan);
    config.threads = args.threads;

    for _ in 0..args.warmup {
        run_search(&config)?;
    }

    let mut runs = Vec::with_capacity(args.loops);
    for _ in 0..args.loops {
        let report = run_search(&config)?;
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
