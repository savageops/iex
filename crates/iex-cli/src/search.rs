use std::{fs, io::Write, path::PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use iex_core::{run_search, ExpressionPlan, SearchConfig};

#[derive(Args, Debug, Clone)]
pub struct SearchArgs {
    #[arg(help = "Expression: lit:text | re:pattern | A && B | A || B")]
    pub expr: String,

    #[arg(
        value_name = "PATH",
        num_args = 0..,
        default_value = ".",
        help = "Files or directories to scan"
    )]
    pub paths: Vec<PathBuf>,

    #[arg(long)]
    pub hidden: bool,

    #[arg(long)]
    pub follow_symlinks: bool,

    #[arg(long)]
    pub json: bool,

    #[arg(long)]
    pub stats_only: bool,

    #[arg(long)]
    pub max_hits: Option<usize>,

    #[arg(short, long)]
    pub threads: Option<usize>,

    #[arg(long)]
    pub emit_report: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchRenderMode {
    Search,
    Matches,
}

pub fn run_search_command(args: SearchArgs) -> Result<()> {
    run_search_with_mode(args, SearchRenderMode::Search)
}

pub fn run_matches_command(args: SearchArgs) -> Result<()> {
    run_search_with_mode(args, SearchRenderMode::Matches)
}

fn run_search_with_mode(args: SearchArgs, mode: SearchRenderMode) -> Result<()> {
    let plan = ExpressionPlan::parse(&args.expr)?;
    let mut config = SearchConfig::from_roots(args.paths.clone(), plan.clone());
    config.include_hidden = args.hidden;
    config.follow_symlinks = args.follow_symlinks;
    config.max_hits = args.max_hits;
    config.threads = args.threads;
    config.collect_hits = !args.stats_only;

    let report = run_search(&config).context("search failed")?;

    if let Some(report_path) = args.emit_report {
        let json = serde_json::to_string_pretty(&report)?;
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create report directory {}", parent.display())
            })?;
        }
        fs::write(&report_path, json)
            .with_context(|| format!("failed to write report to {}", report_path.display()))?;
    }

    if args.json {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        serde_json::to_writer(&mut handle, &report)?;
        handle.write_all(b"\n")?;
        return Ok(());
    }

    if !args.stats_only {
        for hit in &report.hits {
            println!("{}:{}:{}:{}", hit.path, hit.line, hit.column, hit.preview);
        }
    }

    if mode == SearchRenderMode::Search {
        print_search_summary(&report);
    }

    Ok(())
}

fn print_search_summary(report: &iex_core::SearchReport) {
    println!("-- IX Search Summary --");
    println!("expression: {}", report.expression);
    println!("files discovered: {}", report.stats.files_discovered);
    println!("files scanned: {}", report.stats.files_scanned);
    println!("files skipped: {}", report.stats.files_skipped);
    println!("matches found: {}", report.stats.matches_found);
    println!("bytes scanned: {}", report.stats.bytes_scanned);
    println!(
        "timings ms: discover={:.3} scan={:.3} aggregate={:.3} total={:.3}",
        report.stats.timings.discover_ms,
        report.stats.timings.scan_ms,
        report.stats.timings.aggregate_ms,
        report.stats.timings.total_ms,
    );
    if let Some(slowest) = report.stats.slowest_files.first() {
        println!(
            "slowest file: {} ({:.3} ms, {} bytes)",
            slowest.path, slowest.duration_ms, slowest.bytes
        );
    }
}
