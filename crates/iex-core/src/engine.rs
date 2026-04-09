use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use memchr::memchr;
use memmap2::MmapOptions;
use rayon::prelude::*;
use serde::Serialize;

use crate::{expr::ExpressionPlan, stats::SearchStats};

const SMALL_FILE_INLINE_LIMIT: u64 = 256 * 1024;

#[derive(Debug, Clone)]
pub struct SearchConfig {
    pub root: PathBuf,
    pub plan: ExpressionPlan,
    pub include_hidden: bool,
    pub follow_symlinks: bool,
    pub max_hits: Option<usize>,
    pub threads: Option<usize>,
    pub collect_hits: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub preview: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchReport {
    pub expression: String,
    pub hits: Vec<SearchHit>,
    pub stats: SearchStats,
}

#[derive(Debug)]
struct FileScanOutcome {
    path: PathBuf,
    duration_ms: f64,
    bytes: u64,
    hits: Vec<SearchHit>,
    match_count: usize,
    scanned: bool,
}

impl SearchConfig {
    pub fn new(root: PathBuf, plan: ExpressionPlan) -> Self {
        Self {
            root,
            plan,
            include_hidden: false,
            follow_symlinks: false,
            max_hits: None,
            threads: None,
            collect_hits: true,
        }
    }
}

pub fn run_search(config: &SearchConfig) -> Result<SearchReport> {
    run_search_inner(config)
}

fn run_search_inner(config: &SearchConfig) -> Result<SearchReport> {
    let total_started = Instant::now();
    let mut stats = SearchStats::default();

    let discover_started = Instant::now();
    let files = discover_files(config)?;
    stats.timings.discover_ms = discover_started.elapsed().as_secs_f64() * 1_000.0;
    stats.files_discovered = files.len();

    let scan_started = Instant::now();
    let collect_hits = config.collect_hits;
    let resolved_threads = config
        .threads
        .unwrap_or_else(|| auto_threads_for_files(files.len()));
    let mut outcomes: Vec<FileScanOutcome> = if resolved_threads <= 1 {
        files
            .iter()
            .map(|path| scan_file(path, &config.plan, collect_hits))
            .collect()
    } else {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(resolved_threads)
            .build()
            .context("failed to configure rayon thread pool")?;
        pool.install(|| {
            files
                .par_iter()
                .map(|path| scan_file(path, &config.plan, collect_hits))
                .collect()
        })
    };
    stats.timings.scan_ms = scan_started.elapsed().as_secs_f64() * 1_000.0;

    let aggregate_started = Instant::now();
    let mut hits = Vec::new();
    for outcome in outcomes.drain(..) {
        if outcome.scanned {
            stats.files_scanned += 1;
            stats.bytes_scanned += outcome.bytes;
            stats.consider_slow_file(&outcome.path, outcome.duration_ms, outcome.bytes);
            stats.matches_found += outcome.match_count;
            if collect_hits {
                hits.extend(outcome.hits);
            }
        } else {
            stats.files_skipped += 1;
        }
    }

    if collect_hits {
        hits.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
        });
        if let Some(max_hits) = config.max_hits {
            hits.truncate(max_hits);
        }
    }
    stats.timings.aggregate_ms = aggregate_started.elapsed().as_secs_f64() * 1_000.0;
    stats.timings.total_ms = total_started.elapsed().as_secs_f64() * 1_000.0;

    Ok(SearchReport {
        expression: config.plan.source.clone(),
        hits,
        stats,
    })
}

fn discover_files(config: &SearchConfig) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(&config.root);
    builder
        .hidden(!config.include_hidden)
        .follow_links(config.follow_symlinks)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .parents(true);

    let mut files = Vec::new();
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.file_type().is_some_and(|kind| kind.is_file()) {
            files.push(entry.into_path());
        }
    }

    Ok(files)
}

fn auto_threads_for_files(file_count: usize) -> usize {
    let available = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let file_tier = if file_count <= 64 {
        2
    } else if file_count <= 256 {
        4
    } else if file_count <= 1_024 {
        6
    } else {
        8
    };
    available.min(file_tier).max(1)
}

fn scan_file(path: &Path, plan: &ExpressionPlan, collect_hits: bool) -> FileScanOutcome {
    let started = Instant::now();

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return failed_outcome(path, started, 0),
    };

    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return failed_outcome(path, started, 0),
    };

    if metadata.len() <= SMALL_FILE_INLINE_LIMIT {
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        if file.read_to_end(&mut bytes).is_err() {
            return failed_outcome(path, started, metadata.len());
        }
        return scan_loaded_bytes(path, plan, collect_hits, &bytes, metadata.len(), started);
    }

    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(mmap) => mmap,
        Err(_) => return failed_outcome(path, started, metadata.len()),
    };
    scan_loaded_bytes(path, plan, collect_hits, &mmap, metadata.len(), started)
}

fn scan_loaded_bytes(
    path: &Path,
    plan: &ExpressionPlan,
    collect_hits: bool,
    bytes: &[u8],
    file_bytes: u64,
    started: Instant,
) -> FileScanOutcome {
    if bytes.contains(&0) {
        return failed_outcome(path, started, file_bytes);
    }

    let mut hits = Vec::new();
    let mut match_count = 0usize;
    let mut cached_path = None::<String>;

    if !collect_hits {
        if let Some(count) = plan.fast_match_count_no_hits_bytes(bytes) {
            match_count = count;
            return completed_outcome(path, started, file_bytes, hits, match_count);
        }
    }

    if plan.supports_byte_mode() {
        let mut line_start = 0usize;
        let mut line_no = 0usize;

        loop {
            if line_start == bytes.len() {
                break;
            }

            let line_end = match memchr(b'\n', &bytes[line_start..]) {
                Some(offset) => line_start + offset,
                None => bytes.len(),
            };

            let raw_line = &bytes[line_start..line_end];
            let line = if raw_line.last() == Some(&b'\r') {
                &raw_line[..raw_line.len().saturating_sub(1)]
            } else {
                raw_line
            };

            line_no += 1;
            if plan.matches_bytes(line) {
                match_count += 1;
                if collect_hits {
                    hits.push(SearchHit {
                        path: cached_path
                            .get_or_insert_with(|| path.display().to_string())
                            .clone(),
                        line: line_no,
                        column: plan.first_match_column_bytes(line).unwrap_or(1),
                        preview: String::from_utf8_lossy(line).chars().take(220).collect(),
                    });
                }
            }

            if line_end == bytes.len() {
                break;
            }
            line_start = line_end + 1;
        }
    } else {
        let text = String::from_utf8_lossy(bytes);
        if !collect_hits {
            if let Some(count) = plan.fast_match_count_no_hits(&text) {
                match_count = count;
                return completed_outcome(path, started, file_bytes, hits, match_count);
            }
        }

        for (line_idx, line) in text.lines().enumerate() {
            if !plan.matches(line) {
                continue;
            }
            match_count += 1;
            if collect_hits {
                hits.push(SearchHit {
                    path: cached_path
                        .get_or_insert_with(|| path.display().to_string())
                        .clone(),
                    line: line_idx + 1,
                    column: plan.first_match_column(line).unwrap_or(1),
                    preview: line.chars().take(220).collect(),
                });
            }
        }
    }

    completed_outcome(path, started, file_bytes, hits, match_count)
}

fn completed_outcome(
    path: &Path,
    started: Instant,
    bytes: u64,
    hits: Vec<SearchHit>,
    match_count: usize,
) -> FileScanOutcome {
    FileScanOutcome {
        path: path.to_path_buf(),
        duration_ms: started.elapsed().as_secs_f64() * 1_000.0,
        bytes,
        hits,
        match_count,
        scanned: true,
    }
}

fn failed_outcome(path: &Path, started: Instant, bytes: u64) -> FileScanOutcome {
    FileScanOutcome {
        path: path.to_path_buf(),
        duration_ms: started.elapsed().as_secs_f64() * 1_000.0,
        bytes,
        hits: Vec::new(),
        match_count: 0,
        scanned: false,
    }
}
