use std::{fs, io::Write, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use iex_core::{run_search, ExpressionPlan, SearchConfig};

#[derive(Parser, Debug)]
#[command(name = "iex", about = "iEx v2 intelligent expression search CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Search(SearchArgs),
    Explain(ExplainArgs),
}

#[derive(Args, Debug)]
struct SearchArgs {
    #[arg(help = "Expression, e.g. 'lit:error && re:\\btimeout\\b'")]
    expr: String,

    #[arg(default_value = ".", help = "Root path to scan")]
    path: PathBuf,

    #[arg(long)]
    hidden: bool,

    #[arg(long)]
    follow_symlinks: bool,

    #[arg(long)]
    json: bool,

    #[arg(long)]
    stats_only: bool,

    #[arg(long)]
    max_hits: Option<usize>,

    #[arg(short, long)]
    threads: Option<usize>,

    #[arg(long)]
    emit_report: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ExplainArgs {
    #[arg(help = "Expression to parse into iEx plan")]
    expr: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Search(args) => run_search_command(args),
        Command::Explain(args) => run_explain_command(args),
    }
}

fn run_search_command(args: SearchArgs) -> Result<()> {
    let plan = ExpressionPlan::parse(&args.expr)?;
    let mut config = SearchConfig::new(args.path.clone(), plan.clone());
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

    println!("-- iEx Search Summary --");
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

    Ok(())
}

fn run_explain_command(args: ExplainArgs) -> Result<()> {
    let plan = ExpressionPlan::parse(&args.expr)?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer(&mut handle, &plan)?;
    handle.write_all(b"\n")?;
    Ok(())
}
