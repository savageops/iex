use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use anyhow::{Context, Result};
use crossbeam_channel as channel;
use ignore::{WalkBuilder, WalkState};
use memchr::memchr;
use memmap2::MmapOptions;
use rayon::prelude::*;
use serde::Serialize;

use crate::{expr::ExpressionPlan, stats::SearchStats};

const TINY_FILE_INLINE_LIMIT: usize = 16 * 1024;
const SMALL_FILE_INLINE_LIMIT: u64 = 256 * 1024;
const BINARY_SNIFF_LIMIT: usize = 1024;
const PARALLEL_FAST_COUNT_FILE_THRESHOLD: usize = 16 * 1024 * 1024;
const PARALLEL_FAST_COUNT_MEDIUM_MIN_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const PARALLEL_FAST_COUNT_DOMINANT_MIN_CHUNK_BYTES: usize = 32 * 1024 * 1024;
const PARALLEL_FAST_COUNT_TARGET_RANGES_PER_THREAD: usize = 2;
const DOMINANT_FILE_PARALLEL_THRESHOLD: usize = 512 * 1024 * 1024;
const DOMINANT_FILE_PARALLEL_THREAD_CAP_MAX: usize = 12;
const STREAMING_PATH_QUEUE_MULTIPLIER: usize = 4;

#[derive(Debug, Clone)]
pub struct SearchConfig {
    pub roots: Vec<PathBuf>,
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
    shard_plan: Option<ParallelShardPlan>,
}

#[derive(Debug, Default, Clone, Copy)]
struct DiscoveryTelemetry {
    input_roots: usize,
    effective_roots: usize,
    pruned_roots: usize,
    overlap_pruned_roots: usize,
    discovered_duplicate_paths: usize,
}

#[derive(Debug)]
struct DiscoveryResult {
    files: Vec<PathBuf>,
    telemetry: DiscoveryTelemetry,
}

#[derive(Debug)]
struct StreamingScanResult {
    outcomes: Vec<FileScanOutcome>,
    files_discovered: usize,
    duplicate_paths: usize,
    discover_ms: f64,
    scan_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionMode {
    Materialized,
    StreamingStatsOnly,
}

impl ExecutionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Materialized => "materialized",
            Self::StreamingStatsOnly => "streaming_stats_only",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RunConcurrencyPlan {
    available_threads: usize,
    outer_scan_threads: usize,
    execution_mode: ExecutionMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParallelShardPlan {
    shard_threads: usize,
    chunk_bytes: usize,
    range_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct ConcurrencyPlanner {
    available_threads: usize,
}

impl ConcurrencyPlanner {
    fn detect() -> Self {
        Self {
            available_threads: available_threads(),
        }
    }

    fn plan_materialized(
        self,
        requested_threads: Option<usize>,
        file_count: usize,
    ) -> RunConcurrencyPlan {
        let outer_scan_threads = requested_threads
            .map(|threads| threads.max(1))
            .unwrap_or_else(|| {
                auto_threads_for_shape_with_available(file_count, self.available_threads)
            });
        RunConcurrencyPlan {
            available_threads: self.available_threads,
            outer_scan_threads,
            execution_mode: ExecutionMode::Materialized,
        }
    }

    fn plan_streaming(self, requested_threads: Option<usize>) -> RunConcurrencyPlan {
        let outer_scan_threads = requested_threads
            .map(|threads| threads.max(1))
            .unwrap_or_else(|| auto_threads_for_streaming_with_available(self.available_threads));
        RunConcurrencyPlan {
            available_threads: self.available_threads,
            outer_scan_threads,
            execution_mode: ExecutionMode::StreamingStatsOnly,
        }
    }

    fn plan_parallel_fast_count(
        self,
        file_len: usize,
        outer_scan_threads: usize,
    ) -> Option<ParallelShardPlan> {
        parallel_fast_count_plan_with_available(
            file_len,
            outer_scan_threads,
            self.available_threads,
        )
    }
}

#[derive(Clone)]
struct DiscoveryDispatch {
    sender: channel::Sender<PathBuf>,
    seen: Option<Arc<Mutex<BTreeSet<PathBuf>>>>,
    files_discovered: Arc<AtomicUsize>,
    duplicate_paths: Arc<AtomicUsize>,
}

impl SearchConfig {
    pub fn new(root: PathBuf, plan: ExpressionPlan) -> Self {
        Self::from_roots(vec![root], plan)
    }

    pub fn from_roots(mut roots: Vec<PathBuf>, plan: ExpressionPlan) -> Self {
        if roots.is_empty() {
            roots.push(PathBuf::from("."));
        }
        Self {
            roots,
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
    let concurrency = ConcurrencyPlanner::detect();
    let roots = partition_roots(config);
    if should_stream_stats_only(config, &roots) {
        let run_plan = concurrency.plan_streaming(config.threads);
        if run_plan.outer_scan_threads > 1 {
            return run_search_streaming_stats_only(config, roots, concurrency, run_plan);
        }
    }

    run_search_materialized(config, roots, concurrency)
}

fn run_search_materialized(
    config: &SearchConfig,
    roots: RootTargets,
    concurrency: ConcurrencyPlanner,
) -> Result<SearchReport> {
    let total_started = Instant::now();
    let mut stats = SearchStats::default();
    let mut hits = Vec::new();
    let discover_started = Instant::now();
    let discovery = discover_files_from_targets(config, roots)?;
    stats.timings.discover_ms = discover_started.elapsed().as_secs_f64() * 1_000.0;
    stats.input_roots = discovery.telemetry.input_roots;
    stats.effective_roots = discovery.telemetry.effective_roots;
    stats.pruned_roots = discovery.telemetry.pruned_roots;
    stats.overlap_pruned_roots = discovery.telemetry.overlap_pruned_roots;
    stats.discovered_duplicate_paths = discovery.telemetry.discovered_duplicate_paths;
    stats.files_discovered = discovery.files.len();

    let run_plan = concurrency.plan_materialized(config.threads, discovery.files.len());
    stats.set_concurrency_context(
        run_plan.available_threads,
        run_plan.outer_scan_threads,
        run_plan.execution_mode.as_str(),
    );
    let scan_started = Instant::now();
    let mut outcomes = scan_paths(
        &discovery.files,
        &config.plan,
        config.collect_hits,
        concurrency,
        run_plan.outer_scan_threads,
    )?;
    stats.timings.scan_ms = scan_started.elapsed().as_secs_f64() * 1_000.0;

    for outcome in outcomes.drain(..) {
        merge_outcome(&mut stats, &mut hits, config.collect_hits, outcome);
    }

    let aggregate_started = Instant::now();
    if config.collect_hits {
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

#[cfg_attr(not(test), allow(dead_code))]
fn discover_files(config: &SearchConfig) -> Result<DiscoveryResult> {
    let roots = partition_roots(config);
    discover_files_from_targets(config, roots)
}

fn discover_files_from_targets(
    config: &SearchConfig,
    roots: RootTargets,
) -> Result<DiscoveryResult> {
    if roots.directory_roots.is_empty() {
        let files =
            finalize_discovered_files(roots.direct_files, roots.telemetry.effective_roots > 1);
        return Ok(DiscoveryResult {
            files: files.files,
            telemetry: DiscoveryTelemetry {
                discovered_duplicate_paths: files.duplicate_paths,
                ..roots.telemetry
            },
        });
    }

    let needs_dedupe = roots.telemetry.effective_roots > 1;
    let mut files = roots.direct_files;
    files.extend(discover_files_parallel(config, &roots.directory_roots)?);
    let files = finalize_discovered_files(files, needs_dedupe);
    Ok(DiscoveryResult {
        files: files.files,
        telemetry: DiscoveryTelemetry {
            discovered_duplicate_paths: files.duplicate_paths,
            ..roots.telemetry
        },
    })
}

fn prefer_single_root_streaming_stats_only() -> bool {
    !cfg!(windows)
}

fn should_stream_stats_only(config: &SearchConfig, roots: &RootTargets) -> bool {
    !config.collect_hits
        && !roots.directory_roots.is_empty()
        && (roots.telemetry.input_roots > 1 || prefer_single_root_streaming_stats_only())
}

fn build_walk_builder(config: &SearchConfig, roots: &[PathBuf]) -> WalkBuilder {
    let mut builder = WalkBuilder::new(&roots[0]);
    for root in roots.iter().skip(1) {
        builder.add(root);
    }
    builder
        .hidden(!config.include_hidden)
        .follow_links(config.follow_symlinks)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .parents(true);
    builder
}

fn discover_files_parallel(config: &SearchConfig, roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let builder = build_walk_builder(config, roots);
    let (sender, receiver) = channel::unbounded::<PathBuf>();
    let walker = builder.build_parallel();
    walker.run(|| {
        let sender = sender.clone();
        Box::new(move |result| {
            if let Ok(entry) = result {
                if entry.file_type().is_some_and(|kind| kind.is_file()) {
                    let _ = sender.send(entry.into_path());
                }
            }
            WalkState::Continue
        })
    });
    drop(sender);
    let files: Vec<PathBuf> = receiver.into_iter().collect();

    Ok(files)
}

#[derive(Debug)]
struct RootTargets {
    direct_files: Vec<PathBuf>,
    directory_roots: Vec<PathBuf>,
    telemetry: DiscoveryTelemetry,
}

fn partition_roots(config: &SearchConfig) -> RootTargets {
    let normalized = normalize_roots(&config.roots);
    let mut direct_files = Vec::new();
    let mut directory_roots = Vec::new();

    for root in &normalized.roots {
        match root.kind {
            RootKind::File => direct_files.push(root.path.clone()),
            RootKind::Directory => directory_roots.push(root.path.clone()),
        }
    }

    RootTargets {
        direct_files,
        directory_roots,
        telemetry: DiscoveryTelemetry {
            input_roots: config.roots.len(),
            effective_roots: normalized.roots.len(),
            pruned_roots: config.roots.len().saturating_sub(normalized.roots.len()),
            overlap_pruned_roots: normalized.overlap_pruned_roots,
            discovered_duplicate_paths: 0,
        },
    }
}

#[derive(Debug, Clone)]
struct FinalizedFiles {
    files: Vec<PathBuf>,
    duplicate_paths: usize,
}

fn finalize_discovered_files(files: Vec<PathBuf>, dedupe: bool) -> FinalizedFiles {
    if !dedupe {
        return FinalizedFiles {
            files,
            duplicate_paths: 0,
        };
    }
    let mut seen = BTreeSet::new();
    let mut unique = Vec::with_capacity(files.len());
    let mut duplicate_paths = 0usize;
    for path in files {
        if seen.insert(path.clone()) {
            unique.push(path);
        } else {
            duplicate_paths += 1;
        }
    }
    FinalizedFiles {
        files: unique,
        duplicate_paths,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootKind {
    File,
    Directory,
}

#[derive(Debug, Clone)]
struct NormalizedRoot {
    index: usize,
    path: PathBuf,
    canonical: Option<PathBuf>,
    kind: RootKind,
}

#[derive(Debug, Clone)]
struct NormalizedRoots {
    roots: Vec<NormalizedRoot>,
    overlap_pruned_roots: usize,
}

fn normalize_roots(roots: &[PathBuf]) -> NormalizedRoots {
    let candidates: Vec<NormalizedRoot> = roots
        .iter()
        .enumerate()
        .map(|(index, path)| classify_root(index, path))
        .collect();
    let mut retained = Vec::new();
    let mut overlap_pruned_roots = 0usize;

    for candidate in &candidates {
        if has_prior_duplicate(candidate, &candidates) {
            continue;
        }
        if is_pruned_by_overlap(candidate, &candidates) {
            overlap_pruned_roots += 1;
            continue;
        }
        retained.push(candidate.clone());
    }

    retained.sort_by_key(|root| root.index);

    NormalizedRoots {
        roots: retained,
        overlap_pruned_roots,
    }
}

fn classify_root(index: usize, path: &Path) -> NormalizedRoot {
    let kind = if std::fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
    {
        RootKind::File
    } else {
        RootKind::Directory
    };

    NormalizedRoot {
        index,
        path: path.to_path_buf(),
        canonical: std::fs::canonicalize(path).ok(),
        kind,
    }
}

fn has_prior_duplicate(candidate: &NormalizedRoot, roots: &[NormalizedRoot]) -> bool {
    roots
        .iter()
        .filter(|other| other.index < candidate.index)
        .any(|other| roots_equivalent(candidate, other))
}

fn is_pruned_by_overlap(candidate: &NormalizedRoot, roots: &[NormalizedRoot]) -> bool {
    match candidate.kind {
        RootKind::Directory => roots.iter().any(|other| {
            other.index != candidate.index
                && other.kind == RootKind::Directory
                && is_strict_descendant(candidate, other)
        }),
        RootKind::File => roots.iter().any(|other| {
            other.kind == RootKind::Directory && is_strict_descendant(candidate, other)
        }),
    }
}

fn roots_equivalent(left: &NormalizedRoot, right: &NormalizedRoot) -> bool {
    match (left.canonical.as_deref(), right.canonical.as_deref()) {
        (Some(left), Some(right)) => left == right,
        _ => left.path == right.path,
    }
}

fn is_strict_descendant(candidate: &NormalizedRoot, parent: &NormalizedRoot) -> bool {
    let candidate_path = comparable_root_path(candidate);
    let parent_path = comparable_root_path(parent);
    candidate_path != parent_path && candidate_path.starts_with(parent_path)
}

fn comparable_root_path(root: &NormalizedRoot) -> &Path {
    root.canonical.as_deref().unwrap_or(root.path.as_path())
}

fn available_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .max(1)
}

fn threads_90pct(available: usize) -> usize {
    // ceil(available * 0.9) without floats
    // (available * 9 + 9) / 10 is ceil for positive integers.
    let available = available.max(1);
    let desired = (available.saturating_mul(9).saturating_add(9)) / 10;
    desired.clamp(1, available)
}

fn dominant_parallel_thread_cap(shard_budget: usize) -> usize {
    (shard_budget / 4)
        .max(4)
        .min(DOMINANT_FILE_PARALLEL_THREAD_CAP_MAX)
        .max(1)
}

#[allow(dead_code)]
fn auto_threads_for_shape(file_count: usize) -> usize {
    auto_threads_for_shape_with_available(file_count, available_threads())
}

fn auto_threads_for_shape_with_available(file_count: usize, available: usize) -> usize {
    let available = available.max(1);

    let desired = if file_count <= 24 {
        1
    } else if file_count <= 128 {
        4
    } else if file_count < 1_024 {
        8
    } else {
        threads_90pct(available)
    };

    available.min(desired).max(1)
}

#[allow(dead_code)]
fn auto_threads_for_streaming() -> usize {
    auto_threads_for_streaming_with_available(available_threads())
}

fn auto_threads_for_streaming_with_available(available: usize) -> usize {
    threads_90pct(available.max(1))
}

fn run_search_streaming_stats_only(
    config: &SearchConfig,
    roots: RootTargets,
    concurrency: ConcurrencyPlanner,
    run_plan: RunConcurrencyPlan,
) -> Result<SearchReport> {
    let total_started = Instant::now();
    let mut stats = SearchStats::default();
    let hits = Vec::new();
    let streaming =
        scan_paths_streaming_stats_only(config, &roots, concurrency, run_plan.outer_scan_threads)?;

    stats.input_roots = roots.telemetry.input_roots;
    stats.effective_roots = roots.telemetry.effective_roots;
    stats.pruned_roots = roots.telemetry.pruned_roots;
    stats.overlap_pruned_roots = roots.telemetry.overlap_pruned_roots;
    stats.discovered_duplicate_paths = streaming.duplicate_paths;
    stats.files_discovered = streaming.files_discovered;
    stats.timings.discover_ms = streaming.discover_ms;
    stats.timings.scan_ms = streaming.scan_ms;
    stats.set_concurrency_context(
        run_plan.available_threads,
        run_plan.outer_scan_threads,
        run_plan.execution_mode.as_str(),
    );

    let aggregate_started = Instant::now();
    let mut ignored_hits = Vec::new();
    for outcome in streaming.outcomes {
        merge_outcome(&mut stats, &mut ignored_hits, false, outcome);
    }
    stats.timings.aggregate_ms = aggregate_started.elapsed().as_secs_f64() * 1_000.0;
    stats.timings.total_ms = total_started.elapsed().as_secs_f64() * 1_000.0;

    Ok(SearchReport {
        expression: config.plan.source.clone(),
        hits,
        stats,
    })
}

fn scan_paths_streaming_stats_only(
    config: &SearchConfig,
    roots: &RootTargets,
    concurrency: ConcurrencyPlanner,
    resolved_threads: usize,
) -> Result<StreamingScanResult> {
    let queue_depth = resolved_threads
        .saturating_mul(STREAMING_PATH_QUEUE_MULTIPLIER)
        .max(1);
    let (path_sender, path_receiver) = channel::bounded::<PathBuf>(queue_depth);
    let (outcome_sender, outcome_receiver) = channel::unbounded::<FileScanOutcome>();
    let plan = Arc::new(config.plan.clone());
    let dispatch = DiscoveryDispatch::new(path_sender, roots.telemetry.effective_roots > 1);
    let files_discovered = Arc::clone(&dispatch.files_discovered);
    let duplicate_paths = Arc::clone(&dispatch.duplicate_paths);
    let scan_started = Instant::now();

    let (discover_ms, outcomes) =
        std::thread::scope(move |scope| -> Result<(f64, Vec<FileScanOutcome>)> {
            let producer_dispatch = dispatch;
            for _ in 0..resolved_threads {
                let receiver = path_receiver.clone();
                let outcome_sender = outcome_sender.clone();
                let plan = Arc::clone(&plan);
                let concurrency = concurrency;
                scope.spawn(move || {
                    worker_scan_loop(
                        receiver,
                        outcome_sender,
                        plan,
                        concurrency,
                        resolved_threads,
                    );
                });
            }
            drop(path_receiver);
            drop(outcome_sender);

            let discover_started = Instant::now();
            for path in &roots.direct_files {
                if !producer_dispatch.submit(path.clone()) {
                    break;
                }
            }
            discover_files_streaming(config, &roots.directory_roots, &producer_dispatch);
            let discover_ms = discover_started.elapsed().as_secs_f64() * 1_000.0;
            drop(producer_dispatch);

            let mut outcomes = Vec::new();
            for outcome in outcome_receiver {
                outcomes.push(outcome);
            }

            Ok((discover_ms, outcomes))
        })?;

    Ok(StreamingScanResult {
        outcomes,
        files_discovered: files_discovered.load(Ordering::Relaxed),
        duplicate_paths: duplicate_paths.load(Ordering::Relaxed),
        discover_ms,
        scan_ms: scan_started.elapsed().as_secs_f64() * 1_000.0,
    })
}

fn discover_files_streaming(
    config: &SearchConfig,
    roots: &[PathBuf],
    dispatch: &DiscoveryDispatch,
) {
    let builder = build_walk_builder(config, roots);
    let walker = builder.build_parallel();
    walker.run(|| {
        let dispatch = dispatch.clone();
        Box::new(move |result| {
            if let Ok(entry) = result {
                if entry.file_type().is_some_and(|kind| kind.is_file())
                    && !dispatch.submit(entry.into_path())
                {
                    return WalkState::Quit;
                }
            }
            WalkState::Continue
        })
    });
}

fn worker_scan_loop(
    receiver: channel::Receiver<PathBuf>,
    sender: channel::Sender<FileScanOutcome>,
    plan: Arc<ExpressionPlan>,
    concurrency: ConcurrencyPlanner,
    resolved_threads: usize,
) {
    loop {
        let path = match receiver.recv() {
            Ok(path) => path,
            Err(_) => break,
        };
        if sender
            .send(scan_file(
                &path,
                plan.as_ref(),
                false,
                concurrency,
                resolved_threads,
            ))
            .is_err()
        {
            break;
        }
    }
}

impl DiscoveryDispatch {
    fn new(sender: channel::Sender<PathBuf>, dedupe: bool) -> Self {
        Self {
            sender,
            seen: dedupe.then(|| Arc::new(Mutex::new(BTreeSet::new()))),
            files_discovered: Arc::new(AtomicUsize::new(0)),
            duplicate_paths: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn submit(&self, path: PathBuf) -> bool {
        if let Some(seen) = &self.seen {
            let is_new = {
                let mut seen = seen
                    .lock()
                    .expect("streaming discovery set should not be poisoned");
                seen.insert(path.clone())
            };
            if !is_new {
                self.duplicate_paths.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        if self.sender.send(path).is_ok() {
            self.files_discovered.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

fn scan_paths(
    files: &[PathBuf],
    plan: &ExpressionPlan,
    collect_hits: bool,
    concurrency: ConcurrencyPlanner,
    resolved_threads: usize,
) -> Result<Vec<FileScanOutcome>> {
    if resolved_threads <= 1 {
        return Ok(files
            .iter()
            .map(|path| scan_file(path, plan, collect_hits, concurrency, resolved_threads))
            .collect());
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(resolved_threads)
        .build()
        .context("failed to configure rayon thread pool")?;
    Ok(pool.install(|| {
        files
            .par_iter()
            .map(|path| scan_file(path, plan, collect_hits, concurrency, resolved_threads))
            .collect()
    }))
}

fn merge_outcome(
    stats: &mut SearchStats,
    hits: &mut Vec<SearchHit>,
    collect_hits: bool,
    outcome: FileScanOutcome,
) {
    if outcome.scanned {
        stats.files_scanned += 1;
        stats.bytes_scanned += outcome.bytes;
        stats.consider_slow_file(&outcome.path, outcome.duration_ms, outcome.bytes);
        stats.matches_found += outcome.match_count;
        if let Some(shard_plan) = outcome.shard_plan {
            stats.observe_parallel_sharding(
                shard_plan.shard_threads,
                shard_plan.range_count,
                shard_plan.chunk_bytes,
            );
        }
        if collect_hits {
            hits.extend(outcome.hits);
        }
    } else {
        stats.files_skipped += 1;
    }
}

fn scan_file(
    path: &Path,
    plan: &ExpressionPlan,
    collect_hits: bool,
    concurrency: ConcurrencyPlanner,
    outer_scan_threads: usize,
) -> FileScanOutcome {
    let started = Instant::now();
    let mut outcome = {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(_) => return failed_outcome(path, 0),
        };

        let mut tiny = [0u8; TINY_FILE_INLINE_LIMIT];
        let tiny_read = match file.read(&mut tiny) {
            Ok(read) => read,
            Err(_) => return failed_outcome(path, 0),
        };

        if tiny_read < TINY_FILE_INLINE_LIMIT {
            scan_loaded_bytes(
                path,
                plan,
                collect_hits,
                concurrency,
                outer_scan_threads,
                &tiny[..tiny_read],
                tiny_read as u64,
            )
        } else {
            let mut sentinel = [0u8; 1];
            let sentinel_read = match file.read(&mut sentinel) {
                Ok(read) => read,
                Err(_) => return failed_outcome(path, tiny_read as u64),
            };

            if sentinel_read == 0 {
                scan_loaded_bytes(
                    path,
                    plan,
                    collect_hits,
                    concurrency,
                    outer_scan_threads,
                    &tiny,
                    tiny.len() as u64,
                )
            } else {
                let metadata = match file.metadata() {
                    Ok(metadata) => metadata,
                    Err(_) => return failed_outcome(path, (tiny_read + sentinel_read) as u64),
                };

                if metadata.len() <= SMALL_FILE_INLINE_LIMIT {
                    let mut bytes = Vec::with_capacity(metadata.len() as usize);
                    bytes.extend_from_slice(&tiny);
                    bytes.push(sentinel[0]);
                    if file.read_to_end(&mut bytes).is_err() {
                        return failed_outcome(path, metadata.len());
                    }
                    scan_loaded_bytes(
                        path,
                        plan,
                        collect_hits,
                        concurrency,
                        outer_scan_threads,
                        &bytes,
                        metadata.len(),
                    )
                } else {
                    let mmap = match unsafe { MmapOptions::new().map(&file) } {
                        Ok(mmap) => mmap,
                        Err(_) => return failed_outcome(path, metadata.len()),
                    };
                    scan_loaded_bytes(
                        path,
                        plan,
                        collect_hits,
                        concurrency,
                        outer_scan_threads,
                        &mmap,
                        metadata.len(),
                    )
                }
            }
        }
    };
    outcome.duration_ms = started.elapsed().as_secs_f64() * 1_000.0;
    outcome
}

fn scan_loaded_bytes(
    path: &Path,
    plan: &ExpressionPlan,
    collect_hits: bool,
    concurrency: ConcurrencyPlanner,
    outer_scan_threads: usize,
    bytes: &[u8],
    file_bytes: u64,
) -> FileScanOutcome {
    if is_likely_binary(bytes) {
        return failed_outcome(path, file_bytes);
    }

    let mut hits = Vec::new();
    let mut match_count = 0usize;
    let mut cached_path = None::<String>;

    if !collect_hits {
        if let Some((count, shard_plan)) =
            maybe_parallel_fast_count_bytes(plan, bytes, concurrency, outer_scan_threads)
        {
            match_count = count;
            return completed_outcome(path, file_bytes, hits, match_count, Some(shard_plan));
        }
        if let Some(count) = plan.fast_match_count_no_hits_bytes(bytes) {
            match_count = count;
            return completed_outcome(path, file_bytes, hits, match_count, None);
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
            let line = trim_trailing_cr(raw_line);

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
                return completed_outcome(path, file_bytes, hits, match_count, None);
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

    completed_outcome(path, file_bytes, hits, match_count, None)
}

fn is_likely_binary(bytes: &[u8]) -> bool {
    let sniff_len = bytes.len().min(BINARY_SNIFF_LIMIT);
    bytes[..sniff_len].contains(&0)
}

fn maybe_parallel_fast_count_bytes(
    plan: &ExpressionPlan,
    bytes: &[u8],
    concurrency: ConcurrencyPlanner,
    outer_scan_threads: usize,
) -> Option<(usize, ParallelShardPlan)> {
    if outer_scan_threads > 1 && !plan.supports_outer_parallel_shard_fast_count() {
        return None;
    }
    let shard_plan = concurrency.plan_parallel_fast_count(bytes.len(), outer_scan_threads)?;
    let ranges = build_chunk_ranges(bytes.len(), shard_plan.chunk_bytes);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(shard_plan.shard_threads)
        .build()
        .ok()?;
    pool.install(|| {
        ranges
            .par_iter()
            .map(|(start, end)| plan.fast_match_count_no_hits_bytes_in_range(bytes, *start, *end))
            .collect::<Option<Vec<_>>>()
            .map(|counts| (counts.into_iter().sum(), shard_plan))
    })
}

fn parallel_fast_count_min_chunk_bytes(file_len: usize) -> usize {
    if file_len >= DOMINANT_FILE_PARALLEL_THRESHOLD {
        PARALLEL_FAST_COUNT_DOMINANT_MIN_CHUNK_BYTES
    } else {
        PARALLEL_FAST_COUNT_MEDIUM_MIN_CHUNK_BYTES
    }
}

#[allow(dead_code)]
fn parallel_fast_count_plan(
    file_len: usize,
    outer_scan_threads: usize,
) -> Option<ParallelShardPlan> {
    parallel_fast_count_plan_with_available(file_len, outer_scan_threads, available_threads())
}

fn parallel_fast_count_plan_with_available(
    file_len: usize,
    outer_scan_threads: usize,
    available: usize,
) -> Option<ParallelShardPlan> {
    if file_len < PARALLEL_FAST_COUNT_FILE_THRESHOLD {
        return None;
    }

    let available = available.max(1);
    if available <= 1 {
        return None;
    }

    let shard_budget =
        parallel_fast_count_thread_budget_with_available(file_len, outer_scan_threads, available)?;
    let min_chunk_bytes = parallel_fast_count_min_chunk_bytes(file_len);
    let max_range_count = file_len.div_ceil(min_chunk_bytes);
    if max_range_count <= 1 {
        return None;
    }

    let shard_threads = shard_budget.min(max_range_count);
    if shard_threads <= 1 {
        return None;
    }

    let target_range_count = shard_threads
        .saturating_mul(PARALLEL_FAST_COUNT_TARGET_RANGES_PER_THREAD)
        .clamp(2, max_range_count);
    let chunk_bytes = file_len.div_ceil(target_range_count).max(min_chunk_bytes);
    let range_count = build_chunk_ranges(file_len, chunk_bytes).len();
    let shard_threads = shard_threads.min(range_count);
    if shard_threads <= 1 || range_count <= 1 {
        return None;
    }

    Some(ParallelShardPlan {
        shard_threads,
        chunk_bytes,
        range_count,
    })
}

fn parallel_fast_count_thread_budget_with_available(
    file_len: usize,
    outer_scan_threads: usize,
    available: usize,
) -> Option<usize> {
    let shard_budget = threads_90pct(available.max(1));

    if outer_scan_threads <= 1 {
        return (shard_budget > 1).then_some(shard_budget);
    }

    if file_len < PARALLEL_FAST_COUNT_FILE_THRESHOLD {
        return None;
    }

    if file_len < DOMINANT_FILE_PARALLEL_THRESHOLD {
        let medium_threads = shard_budget.min(3);
        return (medium_threads > 1).then_some(medium_threads);
    }

    let dominant_threads = shard_budget.min(dominant_parallel_thread_cap(shard_budget));
    (dominant_threads > 1).then_some(dominant_threads)
}

fn build_chunk_ranges(total_len: usize, chunk_size: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0usize;

    while start < total_len {
        let end = total_len.min(start.saturating_add(chunk_size));
        ranges.push((start, end));
        start = end;
    }

    ranges
}

fn trim_trailing_cr(raw_line: &[u8]) -> &[u8] {
    if raw_line.last() == Some(&b'\r') {
        &raw_line[..raw_line.len().saturating_sub(1)]
    } else {
        raw_line
    }
}

fn completed_outcome(
    path: &Path,
    bytes: u64,
    hits: Vec<SearchHit>,
    match_count: usize,
    shard_plan: Option<ParallelShardPlan>,
) -> FileScanOutcome {
    FileScanOutcome {
        path: path.to_path_buf(),
        duration_ms: 0.0,
        bytes,
        hits,
        match_count,
        scanned: true,
        shard_plan,
    }
}

fn failed_outcome(path: &Path, bytes: u64) -> FileScanOutcome {
    FileScanOutcome {
        path: path.to_path_buf(),
        duration_ms: 0.0,
        bytes,
        hits: Vec::new(),
        match_count: 0,
        scanned: false,
        shard_plan: None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::ExpressionPlan;

    use super::{
        auto_threads_for_shape, auto_threads_for_shape_with_available,
        auto_threads_for_streaming_with_available, discover_files, dominant_parallel_thread_cap,
        parallel_fast_count_min_chunk_bytes, parallel_fast_count_plan_with_available,
        partition_roots, prefer_single_root_streaming_stats_only, run_search,
        should_stream_stats_only, threads_90pct, SearchConfig,
        DOMINANT_FILE_PARALLEL_THREAD_CAP_MAX, DOMINANT_FILE_PARALLEL_THRESHOLD,
        PARALLEL_FAST_COUNT_FILE_THRESHOLD, PARALLEL_FAST_COUNT_MEDIUM_MIN_CHUNK_BYTES,
    };

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{unique}"))
    }

    #[test]
    fn auto_threads_scales_monotonically_with_file_count() {
        let tiny = auto_threads_for_shape(16);
        let medium = auto_threads_for_shape(1_000);
        let huge = auto_threads_for_shape(100_000);
        assert!(tiny >= 1);
        assert!(medium >= tiny);
        assert!(huge >= medium);
    }

    #[test]
    fn auto_threads_uses_parallelism_for_large_corpora_without_byte_samples() {
        assert_eq!(auto_threads_for_shape_with_available(1, 32), 1);
        assert!(auto_threads_for_shape_with_available(2_048, 16) >= 8);
    }

    #[test]
    fn threads_90pct_never_returns_zero_and_never_exceeds_available() {
        for available in [0usize, 1, 2, 3, 4, 8, 16, 32, 64] {
            let resolved = threads_90pct(available);
            assert!(resolved >= 1);
            assert!(resolved <= available.max(1));
        }
    }

    #[test]
    fn auto_threads_for_shape_switches_to_90pct_for_large_file_sets() {
        let available = 32;
        assert_eq!(auto_threads_for_shape_with_available(24, available), 1);
        assert_eq!(auto_threads_for_shape_with_available(128, available), 4);
        assert_eq!(auto_threads_for_shape_with_available(1_023, available), 8);
        assert_eq!(
            auto_threads_for_shape_with_available(1_024, available),
            threads_90pct(available)
        );
    }

    #[test]
    fn auto_threads_for_streaming_uses_90pct_of_available_parallelism() {
        assert_eq!(auto_threads_for_streaming_with_available(1), 1);
        assert_eq!(
            auto_threads_for_streaming_with_available(16),
            threads_90pct(16)
        );
        assert_eq!(
            auto_threads_for_streaming_with_available(32),
            threads_90pct(32)
        );
    }

    #[test]
    fn dominant_parallel_thread_cap_scales_with_budget_but_is_clamped() {
        assert_eq!(dominant_parallel_thread_cap(1), 4);
        assert_eq!(dominant_parallel_thread_cap(4), 4);
        assert_eq!(dominant_parallel_thread_cap(8), 4);
        assert_eq!(dominant_parallel_thread_cap(16), 4);
        assert_eq!(dominant_parallel_thread_cap(28), 7);
        assert_eq!(
            dominant_parallel_thread_cap(64),
            DOMINANT_FILE_PARALLEL_THREAD_CAP_MAX
        );
    }

    #[test]
    fn parallel_fast_count_plan_stays_off_for_small_files() {
        assert_eq!(
            parallel_fast_count_plan_with_available(PARALLEL_FAST_COUNT_FILE_THRESHOLD - 1, 1, 32),
            None
        );
    }

    #[test]
    fn parallel_fast_count_plan_enables_single_threaded_large_files() {
        let file_len = PARALLEL_FAST_COUNT_FILE_THRESHOLD * 4;
        let shard_plan = parallel_fast_count_plan_with_available(file_len, 1, 32)
            .expect("large single-threaded files should parallelize");
        assert!(shard_plan.shard_threads > 1);
        assert!(shard_plan.range_count >= shard_plan.shard_threads);
        assert!(shard_plan.chunk_bytes >= PARALLEL_FAST_COUNT_MEDIUM_MIN_CHUNK_BYTES);
    }

    #[test]
    fn parallel_fast_count_plan_enables_giant_file_override_under_outer_parallelism() {
        let shard_plan =
            parallel_fast_count_plan_with_available(DOMINANT_FILE_PARALLEL_THRESHOLD, 16, 32)
                .expect("dominant giant files should get an inner parallel override");
        assert!(shard_plan.shard_threads > 1);
        assert!(shard_plan.shard_threads <= DOMINANT_FILE_PARALLEL_THREAD_CAP_MAX);
        assert!(shard_plan.range_count >= shard_plan.shard_threads);
    }

    #[test]
    fn parallel_fast_count_plan_enables_outer_parallel_large_files_with_capped_budget() {
        let file_len = PARALLEL_FAST_COUNT_FILE_THRESHOLD * 4;
        let shard_plan = parallel_fast_count_plan_with_available(file_len, 8, 32)
            .expect("outer-parallel large files should receive a capped inner shard budget");
        assert_eq!(shard_plan.shard_threads, 3);
        assert!(shard_plan.range_count >= shard_plan.shard_threads);
    }

    #[test]
    fn parallel_fast_count_plan_feeds_threads_with_multiple_ranges_on_mid_size_files() {
        let file_len = 144 * 1024 * 1024;
        let shard_plan = parallel_fast_count_plan_with_available(file_len, 1, 32)
            .expect("mid-size shard-safe files should parallelize");
        assert!(shard_plan.shard_threads > 1);
        assert!(shard_plan.range_count >= shard_plan.shard_threads);
        assert!(
            shard_plan.chunk_bytes >= parallel_fast_count_min_chunk_bytes(file_len),
            "chunk floor should stay dynamic per file shape"
        );
    }

    #[test]
    fn parallel_fast_count_plan_enables_two_range_files_at_threshold_plus_epsilon() {
        let file_len = PARALLEL_FAST_COUNT_FILE_THRESHOLD + 4 * 1024;
        let shard_plan = parallel_fast_count_plan_with_available(file_len, 8, 32)
            .expect("two-range files should parallelize when shard budget allows");
        assert!(shard_plan.shard_threads >= 2);
        assert!(shard_plan.range_count >= 2);
    }

    #[test]
    fn auto_search_handles_small_corpus_end_to_end() {
        let root = unique_temp_path("iex-engine-small-corpus");
        fs::create_dir_all(&root).expect("temp corpus should be created");
        fs::write(root.join("one.txt"), "alpha\nneedle here\n")
            .expect("first fixture should write");
        fs::write(root.join("two.txt"), "needle again\n").expect("second fixture should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let report =
            run_search(&SearchConfig::new(root.clone(), plan)).expect("search should succeed");

        assert_eq!(report.stats.files_discovered, 2);
        assert_eq!(report.stats.files_scanned, 2);
        assert_eq!(report.stats.files_skipped, 0);
        assert_eq!(report.stats.matches_found, 2);
        assert_eq!(report.stats.input_roots, 1);
        assert_eq!(report.stats.effective_roots, 1);
        assert_eq!(report.stats.pruned_roots, 0);
        assert_eq!(report.stats.overlap_pruned_roots, 0);
        assert_eq!(report.stats.discovered_duplicate_paths, 0);
        assert_eq!(report.stats.acceleration_bailouts, 0);
        assert_eq!(report.stats.concurrency.execution_mode, "materialized");
        assert_eq!(report.stats.concurrency.outer_scan_threads, 1);
        assert!(report.stats.concurrency.available_threads >= 1);
        assert!(!report.stats.concurrency.sharding_enabled);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discover_files_treats_direct_file_root_as_single_scan_target() {
        let root = unique_temp_path("iex-engine-file-root").with_extension("txt");
        fs::write(&root, "needle here\n").expect("fixture file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let config = SearchConfig::new(root.clone(), plan);
        let discovery = discover_files(&config).expect("single file discovery should succeed");

        assert_eq!(discovery.files, vec![root.clone()]);
        assert_eq!(discovery.telemetry.input_roots, 1);
        assert_eq!(discovery.telemetry.effective_roots, 1);
        assert_eq!(discovery.telemetry.pruned_roots, 0);
        assert_eq!(discovery.telemetry.overlap_pruned_roots, 0);
        assert_eq!(discovery.telemetry.discovered_duplicate_paths, 0);

        let _ = fs::remove_file(root);
    }

    #[test]
    fn discover_files_supports_multiple_directory_roots() {
        let root = unique_temp_path("iex-engine-multi-root");
        let left = root.join("left");
        let right = root.join("right");
        fs::create_dir_all(&left).expect("left dir should be created");
        fs::create_dir_all(&right).expect("right dir should be created");
        fs::write(left.join("one.txt"), "needle left\n").expect("left file should write");
        fs::write(right.join("two.txt"), "needle right\n").expect("right file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let config = SearchConfig::from_roots(vec![left.clone(), right.clone()], plan);
        let discovery = discover_files(&config).expect("multi-root discovery should succeed");

        assert_eq!(discovery.files.len(), 2);
        assert!(discovery.files.contains(&left.join("one.txt")));
        assert!(discovery.files.contains(&right.join("two.txt")));
        assert_eq!(discovery.telemetry.input_roots, 2);
        assert_eq!(discovery.telemetry.effective_roots, 2);
        assert_eq!(discovery.telemetry.pruned_roots, 0);
        assert_eq!(discovery.telemetry.overlap_pruned_roots, 0);
        assert_eq!(discovery.telemetry.discovered_duplicate_paths, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discover_files_dedupes_file_root_under_directory_root() {
        let root = unique_temp_path("iex-engine-overlap-root");
        fs::create_dir_all(&root).expect("root dir should be created");
        let file = root.join("needle.txt");
        fs::write(&file, "needle here\n").expect("fixture file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let config = SearchConfig::from_roots(vec![root.clone(), file.clone()], plan);
        let discovery = discover_files(&config).expect("overlap discovery should succeed");

        assert_eq!(discovery.files, vec![file.clone()]);
        assert_eq!(discovery.telemetry.input_roots, 2);
        assert_eq!(discovery.telemetry.effective_roots, 1);
        assert_eq!(discovery.telemetry.pruned_roots, 1);
        assert_eq!(discovery.telemetry.overlap_pruned_roots, 1);
        assert_eq!(discovery.telemetry.discovered_duplicate_paths, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discover_files_prunes_duplicate_directory_roots_before_walk() {
        let root = unique_temp_path("iex-engine-duplicate-root");
        fs::create_dir_all(&root).expect("root dir should be created");
        let file = root.join("needle.txt");
        fs::write(&file, "needle here\n").expect("fixture file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let config = SearchConfig::from_roots(vec![root.clone(), root.clone()], plan);
        let discovery = discover_files(&config).expect("duplicate root discovery should succeed");

        assert_eq!(discovery.files, vec![file.clone()]);
        assert_eq!(discovery.telemetry.input_roots, 2);
        assert_eq!(discovery.telemetry.effective_roots, 1);
        assert_eq!(discovery.telemetry.pruned_roots, 1);
        assert_eq!(discovery.telemetry.overlap_pruned_roots, 0);
        assert_eq!(discovery.telemetry.discovered_duplicate_paths, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discover_files_prunes_child_directory_even_when_parent_is_later() {
        let root = unique_temp_path("iex-engine-parent-child-root");
        let child = root.join("nested");
        fs::create_dir_all(&child).expect("child dir should be created");
        let file = child.join("needle.txt");
        fs::write(&file, "needle here\n").expect("fixture file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let config = SearchConfig::from_roots(vec![child.clone(), root.clone()], plan);
        let discovery =
            discover_files(&config).expect("parent-child root discovery should succeed");

        assert_eq!(discovery.files, vec![file.clone()]);
        assert_eq!(discovery.telemetry.input_roots, 2);
        assert_eq!(discovery.telemetry.effective_roots, 1);
        assert_eq!(discovery.telemetry.pruned_roots, 1);
        assert_eq!(discovery.telemetry.overlap_pruned_roots, 1);
        assert_eq!(discovery.telemetry.discovered_duplicate_paths, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discover_files_prunes_contained_file_even_when_directory_is_later() {
        let root = unique_temp_path("iex-engine-file-parent-root");
        fs::create_dir_all(&root).expect("root dir should be created");
        let file = root.join("needle.txt");
        fs::write(&file, "needle here\n").expect("fixture file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let config = SearchConfig::from_roots(vec![file.clone(), root.clone()], plan);
        let discovery =
            discover_files(&config).expect("mixed file-directory discovery should succeed");

        assert_eq!(discovery.files, vec![file.clone()]);
        assert_eq!(discovery.telemetry.input_roots, 2);
        assert_eq!(discovery.telemetry.effective_roots, 1);
        assert_eq!(discovery.telemetry.pruned_roots, 1);
        assert_eq!(discovery.telemetry.overlap_pruned_roots, 1);
        assert_eq!(discovery.telemetry.discovered_duplicate_paths, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn run_search_supports_multiple_roots_end_to_end() {
        let root = unique_temp_path("iex-engine-search-multi-root");
        let left = root.join("left");
        let right = root.join("right");
        fs::create_dir_all(&left).expect("left dir should be created");
        fs::create_dir_all(&right).expect("right dir should be created");
        fs::write(left.join("one.txt"), "alpha\nneedle left\n").expect("left file should write");
        fs::write(right.join("two.txt"), "needle right\n").expect("right file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let report = run_search(&SearchConfig::from_roots(
            vec![left.clone(), right.clone()],
            plan,
        ))
        .expect("multi-root search should succeed");

        assert_eq!(report.stats.files_discovered, 2);
        assert_eq!(report.stats.files_scanned, 2);
        assert_eq!(report.stats.matches_found, 2);
        assert_eq!(report.stats.input_roots, 2);
        assert_eq!(report.stats.effective_roots, 2);
        assert_eq!(report.stats.pruned_roots, 0);
        assert_eq!(report.stats.overlap_pruned_roots, 0);
        assert_eq!(report.stats.discovered_duplicate_paths, 0);
        assert_eq!(report.stats.acceleration_bailouts, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn run_search_stats_only_streams_single_directory_root_without_changing_totals() {
        let root = unique_temp_path("iex-engine-search-stats-only");
        fs::create_dir_all(&root).expect("root dir should be created");
        fs::write(root.join("one.txt"), "alpha\nneedle here\n")
            .expect("first fixture should write");
        fs::write(root.join("two.txt"), "needle again\nbeta\n")
            .expect("second fixture should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let collecting = run_search(&SearchConfig::new(root.clone(), plan.clone()))
            .expect("collecting search should succeed");

        let mut stats_only_config = SearchConfig::new(root.clone(), plan);
        stats_only_config.collect_hits = false;
        let stats_only = run_search(&stats_only_config).expect("stats-only search should succeed");

        assert!(stats_only.hits.is_empty());
        assert_eq!(
            stats_only.stats.files_discovered,
            collecting.stats.files_discovered
        );
        assert_eq!(
            stats_only.stats.files_scanned,
            collecting.stats.files_scanned
        );
        assert_eq!(
            stats_only.stats.files_skipped,
            collecting.stats.files_skipped
        );
        assert_eq!(
            stats_only.stats.matches_found,
            collecting.stats.matches_found
        );
        assert_eq!(
            stats_only.stats.bytes_scanned,
            collecting.stats.bytes_scanned
        );
        assert_eq!(stats_only.stats.input_roots, 1);
        assert_eq!(stats_only.stats.effective_roots, 1);
        assert_eq!(stats_only.stats.pruned_roots, 0);
        assert_eq!(stats_only.stats.overlap_pruned_roots, 0);
        assert_eq!(stats_only.stats.discovered_duplicate_paths, 0);
        assert_eq!(stats_only.stats.acceleration_bailouts, 0);
        assert_eq!(
            stats_only.stats.concurrency.execution_mode,
            if prefer_single_root_streaming_stats_only() {
                "streaming_stats_only"
            } else {
                "materialized"
            }
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn run_search_stats_only_preserves_overlap_pruning_for_mixed_roots() {
        let root = unique_temp_path("iex-engine-search-overlap-stats-only");
        fs::create_dir_all(&root).expect("root dir should be created");
        let file = root.join("needle.txt");
        fs::write(&file, "needle here\n").expect("fixture file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let mut config = SearchConfig::from_roots(vec![root.clone(), file.clone()], plan);
        config.collect_hits = false;
        let report = run_search(&config).expect("stats-only overlap search should succeed");

        assert!(report.hits.is_empty());
        assert_eq!(report.stats.files_discovered, 1);
        assert_eq!(report.stats.files_scanned, 1);
        assert_eq!(report.stats.files_skipped, 0);
        assert_eq!(report.stats.matches_found, 1);
        assert_eq!(report.stats.input_roots, 2);
        assert_eq!(report.stats.effective_roots, 1);
        assert_eq!(report.stats.pruned_roots, 1);
        assert_eq!(report.stats.overlap_pruned_roots, 1);
        assert_eq!(report.stats.discovered_duplicate_paths, 0);
        assert_eq!(report.stats.acceleration_bailouts, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stats_only_streaming_gate_stays_on_for_single_root_directory_searches() {
        let root = unique_temp_path("iex-engine-streaming-gate-single-root");
        fs::create_dir_all(&root).expect("root dir should be created");
        fs::write(root.join("needle.txt"), "needle here\n").expect("fixture file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let mut config = SearchConfig::new(root.clone(), plan);
        config.collect_hits = false;
        let roots = partition_roots(&config);

        assert_eq!(
            should_stream_stats_only(&config, &roots),
            prefer_single_root_streaming_stats_only()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stats_only_streaming_gate_stays_on_for_multipath_even_after_overlap_pruning() {
        let root = unique_temp_path("iex-engine-streaming-gate-multipath");
        let child = root.join("nested");
        fs::create_dir_all(&child).expect("child dir should be created");
        fs::write(child.join("needle.txt"), "needle here\n").expect("fixture file should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let mut config = SearchConfig::from_roots(vec![root.clone(), child.clone()], plan);
        config.collect_hits = false;
        let roots = partition_roots(&config);

        assert_eq!(roots.telemetry.input_roots, 2);
        assert_eq!(roots.telemetry.effective_roots, 1);
        assert!(should_stream_stats_only(&config, &roots));

        let _ = fs::remove_dir_all(root);
    }
}
