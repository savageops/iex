use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use clap::Args;
use iex_core::{
    inspect_window, run_search, ExpressionPlan, InspectLine, InspectWindowReport,
    InspectWindowRequest, SearchConfig,
};
use serde_json::json;

#[derive(Args, Debug, Clone)]
#[command(
    after_help = "SNIPS\n  ix inspect src/main.rs --total-count 40\n  ix inspect src/main.rs --skip 120 --limit 30\n  ix inspect src/main.rs --range 40:80\n  ix inspect --expr 'lit:SearchConfig' crates --context 2 --json"
)]
pub struct InspectArgs {
    #[arg(value_name = "PATH", num_args = 1.., help = "Files or search roots")]
    pub paths: Vec<PathBuf>,

    #[arg(long = "total-count", alias = "head", help = "Emit first N lines")]
    pub total_count: Option<usize>,

    #[arg(long, help = "Skip N lines before emitting")]
    pub skip: Option<usize>,

    #[arg(long, help = "Emit at most N lines")]
    pub limit: Option<usize>,

    #[arg(long = "start-line", help = "Inclusive 1-based start line")]
    pub start_line: Option<usize>,

    #[arg(long = "end-line", help = "Inclusive 1-based end line")]
    pub end_line: Option<usize>,

    #[arg(long, value_parser = parse_line_range, help = "Inclusive START:END line range")]
    pub range: Option<LineRangeArg>,

    #[arg(long, help = "Allow explicit full/tail file output")]
    pub all: bool,

    #[arg(long, help = "Emit JSON")]
    pub json: bool,

    #[arg(
        long,
        value_name = "EXPR",
        help = "IX expression for match-context mode"
    )]
    pub expr: Option<String>,

    #[arg(
        short = 'C',
        long = "context",
        help = "Lines before and after each match"
    )]
    pub context: Option<usize>,

    #[arg(short = 'B', long = "before-context", help = "Lines before each match")]
    pub before_context: Option<usize>,

    #[arg(short = 'A', long = "after-context", help = "Lines after each match")]
    pub after_context: Option<usize>,

    #[arg(long)]
    pub hidden: bool,

    #[arg(long)]
    pub follow_symlinks: bool,

    #[arg(short, long)]
    pub threads: Option<usize>,

    #[arg(long)]
    pub max_hits: Option<usize>,

    #[arg(long, hide = true)]
    pub replace: Option<String>,

    #[arg(long, hide = true)]
    pub write: bool,

    #[arg(long = "in-place", hide = true)]
    pub in_place: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LineRangeArg {
    pub start: usize,
    pub end: usize,
}

pub fn run_inspect_command(args: InspectArgs) -> Result<()> {
    reject_mutation_shape(&args)?;
    if args.expr.is_some() {
        run_match_context(args)
    } else {
        run_file_windows(args)
    }
}

fn reject_mutation_shape(args: &InspectArgs) -> Result<()> {
    if args.replace.is_some() || args.write || args.in_place {
        bail!("ix inspect is read-only; replacement and write flags belong to a future transform command");
    }
    Ok(())
}

fn run_file_windows(args: InspectArgs) -> Result<()> {
    if args.has_context_flags() {
        bail!("match context requires --expr so IX search owns hit discovery");
    }

    let reports: Vec<InspectWindowReport> = args
        .paths
        .iter()
        .map(|path| inspect_window(&window_request_for_path(&args, path.clone())?))
        .collect::<Result<Vec<_>>>()?;

    if args.json {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        serde_json::to_writer(&mut handle, &json!({ "reports": reports }))?;
        handle.write_all(b"\n")?;
        return Ok(());
    }

    for report in &reports {
        print_window_report(report);
    }
    Ok(())
}

fn run_match_context(args: InspectArgs) -> Result<()> {
    if args.range.is_some()
        || args.total_count.is_some()
        || args.skip.is_some()
        || args.limit.is_some()
        || args.start_line.is_some()
        || args.end_line.is_some()
        || args.all
    {
        bail!("match-context inspection accepts --expr with --context/--before-context/--after-context, not file-window bounds");
    }

    let expr = args
        .expr
        .clone()
        .expect("expr mode is checked before context inspection");
    let plan = ExpressionPlan::parse(&expr)?;
    let mut config = SearchConfig::from_roots(args.paths.clone(), plan);
    config.include_hidden = args.hidden;
    config.follow_symlinks = args.follow_symlinks;
    config.max_hits = args.max_hits;
    config.threads = args.threads;
    config.collect_hits = true;

    let report = run_search(&config).context("inspect context search failed")?;
    let before = args.before_context.or(args.context).unwrap_or(0);
    let after = args.after_context.or(args.context).unwrap_or(0);
    let context = build_context_reports(&report.hits, before, after)?;

    if args.json {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        serde_json::to_writer(
            &mut handle,
            &json!({
                "expression": report.expression,
                "reports": context.iter().map(ContextFileReport::to_json).collect::<Vec<_>>()
            }),
        )?;
        handle.write_all(b"\n")?;
        return Ok(());
    }

    for file in &context {
        for line in &file.lines {
            println!("{}:{}:{}:{}", file.path, line.line, line.role, line.text);
        }
    }
    Ok(())
}

fn window_request_for_path(args: &InspectArgs, path: PathBuf) -> Result<InspectWindowRequest> {
    if args.range.is_some()
        && (args.total_count.is_some()
            || args.skip.is_some()
            || args.limit.is_some()
            || args.start_line.is_some()
            || args.end_line.is_some()
            || args.all)
    {
        bail!("--range cannot be combined with other file-window bounds");
    }
    if args.total_count.is_some()
        && (args.skip.is_some()
            || args.limit.is_some()
            || args.start_line.is_some()
            || args.end_line.is_some()
            || args.all)
    {
        bail!("--total-count cannot be combined with other file-window bounds");
    }

    if let Some(range) = args.range {
        return Ok(InspectWindowRequest::range(path, range.start, range.end));
    }
    if let Some(total_count) = args.total_count {
        return Ok(InspectWindowRequest::first(path, total_count));
    }

    Ok(InspectWindowRequest {
        path,
        start_line: args.start_line,
        end_line: args.end_line,
        skip: args.skip.unwrap_or(0),
        limit: args.limit,
        allow_full: args.all,
    })
}

fn print_window_report(report: &InspectWindowReport) {
    for line in &report.lines {
        println!("{}:{}:{}", report.path, line.line, line.text);
    }
}

fn build_context_reports(
    hits: &[iex_core::SearchHit],
    before: usize,
    after: usize,
) -> Result<Vec<ContextFileReport>> {
    let mut by_path: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for hit in hits {
        by_path
            .entry(hit.path.clone())
            .or_default()
            .insert(hit.line);
    }

    let mut files = Vec::new();
    for (path, match_lines) in by_path {
        let ranges = merge_ranges(
            match_lines
                .iter()
                .map(|line| (line.saturating_sub(before).max(1), line + after))
                .collect(),
        );
        let mut lines = Vec::new();
        for (start, end) in ranges {
            let report = inspect_window(&InspectWindowRequest::range(&path, start, end))?;
            for line in report.lines {
                let role = if match_lines.contains(&line.line) {
                    "match"
                } else {
                    "context"
                };
                lines.push(ContextLine {
                    line: line.line,
                    text: line.text,
                    role,
                });
            }
        }
        files.push(ContextFileReport { path, lines });
    }
    Ok(files)
}

fn merge_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        let Some(last) = merged.last_mut() else {
            merged.push((start, end));
            continue;
        };
        if start <= last.1 + 1 {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

fn parse_line_range(value: &str) -> Result<LineRangeArg, String> {
    let Some((start, end)) = value.split_once(':') else {
        return Err("range must use START:END".to_owned());
    };
    let start = start
        .parse::<usize>()
        .map_err(|_| "range start must be a positive integer".to_owned())?;
    let end = end
        .parse::<usize>()
        .map_err(|_| "range end must be a positive integer".to_owned())?;
    if start == 0 || end == 0 {
        return Err("range lines must be greater than zero".to_owned());
    }
    if start > end {
        return Err("range start must be less than or equal to end".to_owned());
    }
    Ok(LineRangeArg { start, end })
}

impl InspectArgs {
    fn has_context_flags(&self) -> bool {
        self.context.is_some() || self.before_context.is_some() || self.after_context.is_some()
    }
}

struct ContextFileReport {
    path: String,
    lines: Vec<ContextLine>,
}

impl ContextFileReport {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "path": self.path,
            "lines": self.lines.iter().map(ContextLine::to_json).collect::<Vec<_>>()
        })
    }
}

struct ContextLine {
    line: usize,
    text: String,
    role: &'static str,
}

impl ContextLine {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "line": self.line,
            "text": self.text,
            "role": self.role
        })
    }
}

#[allow(dead_code)]
fn _assert_core_line_type_is_owned(_: &InspectLine) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;

    #[test]
    fn parses_range_argument() {
        let range = parse_line_range("3:9").unwrap();

        assert_eq!(range, LineRangeArg { start: 3, end: 9 });
    }

    #[test]
    fn rejects_inverted_range_argument() {
        let error = parse_line_range("9:3").unwrap_err();

        assert!(error.contains("less than or equal"));
    }

    #[test]
    fn routes_inspect_as_canonical_command() {
        let cli = Cli::try_parse_from(["ix", "inspect", "Cargo.toml", "--total-count", "2"])
            .expect("inspect command should parse");

        assert!(matches!(cli.command, crate::Command::Inspect(_)));
    }

    #[test]
    fn window_request_lowers_total_count() {
        let args = InspectArgs {
            paths: vec![PathBuf::from("Cargo.toml")],
            total_count: Some(5),
            skip: None,
            limit: None,
            start_line: None,
            end_line: None,
            range: None,
            all: false,
            json: false,
            expr: None,
            context: None,
            before_context: None,
            after_context: None,
            hidden: false,
            follow_symlinks: false,
            threads: None,
            max_hits: None,
            replace: None,
            write: false,
            in_place: false,
        };

        let request = window_request_for_path(&args, PathBuf::from("Cargo.toml")).unwrap();

        assert_eq!(request.start_line, Some(1));
        assert_eq!(request.limit, Some(5));
    }

    #[test]
    fn merge_ranges_coalesces_overlapping_context() {
        assert_eq!(
            merge_ranges(vec![(1, 3), (3, 6), (9, 10)]),
            vec![(1, 6), (9, 10)]
        );
    }
}
