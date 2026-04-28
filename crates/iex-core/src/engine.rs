use std::{
    cmp::Ordering as CmpOrdering,
    collections::{BTreeSet, HashMap},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Instant,
};

use anyhow::{bail, Context, Result};
use crossbeam_channel as channel;
use ignore::{WalkBuilder, WalkState};
use memchr::memchr;
use memmap2::MmapOptions;
use rayon::prelude::*;
use serde::Serialize;

use crate::{
    expr::{ExpressionPlan, FastCountOutcome, FastDecompositionResult},
    stats::{
        ByteShardKernelStats, FallbackLineScanStats, FastCountDensityStats, LinuxStrategyStats,
        RegexDecompositionStats, SearchStats, UnicodeCaseFoldPrefilterStats,
    },
};

const TINY_FILE_INLINE_LIMIT: usize = 16 * 1024;
const SMALL_FILE_INLINE_LIMIT: u64 = 256 * 1024;
const BINARY_SNIFF_LIMIT: usize = 1024;
const PARALLEL_FAST_COUNT_FILE_THRESHOLD: usize = 16 * 1024 * 1024;
const PARALLEL_FAST_COUNT_MEDIUM_MIN_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const PARALLEL_FAST_COUNT_DOMINANT_MIN_CHUNK_BYTES: usize = 32 * 1024 * 1024;
const PARALLEL_FAST_COUNT_TARGET_RANGES_PER_THREAD: usize = 2;
const PARALLEL_FAST_COUNT_OUTER_LITERAL_MEDIUM_THREAD_CAP: usize = 2;
const REGEX_DECOMPOSITION_PARALLEL_FILE_THRESHOLD: usize = 64 * 1024 * 1024;
const REGEX_DECOMPOSITION_PARALLEL_MAX_SHARD_THREADS: usize = 2;
const DOMINANT_FILE_PARALLEL_THRESHOLD: usize = 512 * 1024 * 1024;
const DOMINANT_FILE_PARALLEL_THREAD_CAP_MAX: usize = 12;
const STREAMING_PATH_QUEUE_MULTIPLIER: usize = 4;
const LINUX_STRATEGY_MIN_ROOT_ENTRIES: usize = 32;
const LINUX_STRATEGY_MIN_FILES: usize = 50_000;
const LINUX_DOMINANT_FILE_TARGET_CLASS: &str = "linux_amd_asic_reg_giant_header";
const LINUX_DOMINANT_FILE_MIN_BYTES: u64 = 8 * 1024 * 1024;
const LINUX_DOMINANT_FILE_MAX_SHARD_THREADS: usize = 3;
const LINUX_DOMINANT_FILE_TARGET_RANGES_PER_THREAD: usize = 2;
const LINUX_DOMINANT_FILE_COMPONENTS: [&str; 8] = [
    "benchsuite",
    "linux",
    "drivers",
    "gpu",
    "drm",
    "amd",
    "include",
    "asic_reg",
];

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedSearchOptions {
    pub include_hidden: bool,
    pub follow_symlinks: bool,
}

#[derive(Debug, Clone)]
pub struct PreparedSearchTargets {
    roots: Arc<[PathBuf]>,
    files: Arc<[PathBuf]>,
    path_depths: Arc<[u16]>,
    path_index_by_path: Arc<OnceLock<HashMap<PathBuf, usize>>>,
    options: PreparedSearchOptions,
    telemetry: DiscoveryTelemetry,
    directory_root_count: usize,
    root_entry_count: usize,
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
    path: Option<PathBuf>,
    path_index: Option<usize>,
    duration_ms: f64,
    bytes: u64,
    hits: Vec<SearchHit>,
    match_count: usize,
    acceleration_bailouts: usize,
    regex_decomposition: RegexDecompositionStats,
    unicode_casefold_prefilter: UnicodeCaseFoldPrefilterStats,
    fast_count_density: FastCountDensityStats,
    byte_shard_kernel: ByteShardKernelStats,
    fallback_line_scan: Option<Box<FallbackLineScanStats>>,
    scanned: bool,
    shard_plan: Option<ParallelShardPlan>,
    linux_dominant_target: bool,
    linux_dominant_file: LinuxDominantFileExecution,
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
    directory_root_count: usize,
    root_entry_count: usize,
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

#[derive(Debug)]
struct ShardRangeCount {
    outcome: FastCountOutcome,
    kernel: ByteShardKernelStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionMode {
    Materialized,
    MaterializedPrepared,
    StreamingStatsOnly,
}

impl ExecutionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Materialized => "materialized",
            Self::MaterializedPrepared => "materialized_prepared",
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

#[derive(Debug, Clone, Copy)]
struct LinuxStrategyInputs {
    matcher_strategy_supported: bool,
    effective_roots: usize,
    directory_roots: usize,
    root_entry_count: usize,
    files_discovered: usize,
    collect_hits: bool,
    outer_parallel_shard_safe: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct LinuxDominantFileExecution {
    eligible: bool,
    activated: bool,
    bailed_out: bool,
    shard_threads: usize,
    range_count: usize,
    chunk_bytes: usize,
}

fn linux_strategy_prefers_streaming(inputs: LinuxStrategyInputs) -> bool {
    inputs.matcher_strategy_supported
        && !inputs.collect_hits
        && inputs.effective_roots == 1
        && inputs.directory_roots == 1
        && inputs.root_entry_count >= LINUX_STRATEGY_MIN_ROOT_ENTRIES
}

fn linux_strategy_selector_eligible(inputs: LinuxStrategyInputs) -> bool {
    linux_strategy_prefers_streaming(inputs) && inputs.files_discovered >= LINUX_STRATEGY_MIN_FILES
}

fn linux_strategy_stats(inputs: LinuxStrategyInputs, current_strategy: &str) -> LinuxStrategyStats {
    let mut telemetry = LinuxStrategyStats::default();
    telemetry.selector_eligible = linux_strategy_selector_eligible(inputs);
    telemetry.current_strategy.push_str(current_strategy);
    telemetry.matcher_strategy_supported = inputs.matcher_strategy_supported;
    telemetry.effective_roots = inputs.effective_roots;
    telemetry.directory_roots = inputs.directory_roots;
    telemetry.root_entry_count = inputs.root_entry_count;
    telemetry.files_discovered = inputs.files_discovered;
    telemetry.collect_hits = inputs.collect_hits;
    telemetry.outer_parallel_shard_safe = inputs.outer_parallel_shard_safe;
    telemetry
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

    fn plan_materialized_prepared(
        self,
        requested_threads: Option<usize>,
        file_count: usize,
    ) -> RunConcurrencyPlan {
        let mut plan = self.plan_materialized(requested_threads, file_count);
        plan.execution_mode = ExecutionMode::MaterializedPrepared;
        plan
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
        dominant_literal_scan: bool,
    ) -> Option<ParallelShardPlan> {
        parallel_fast_count_plan_with_available(
            file_len,
            outer_scan_threads,
            self.available_threads,
            dominant_literal_scan,
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

impl PreparedSearchTargets {
    pub fn discover(roots: Vec<PathBuf>, options: PreparedSearchOptions) -> Result<Self> {
        let partitioned = partition_root_paths(&roots);
        let discovery = discover_files_with_options(options, partitioned)?;
        Ok(Self::from_discovery(roots, options, discovery))
    }

    pub fn from_config(config: &SearchConfig) -> Result<Self> {
        Self::discover(config.roots.clone(), search_options(config))
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn files(&self) -> &[PathBuf] {
        self.files.as_ref()
    }

    pub fn roots(&self) -> &[PathBuf] {
        self.roots.as_ref()
    }

    pub fn max_path_depth(&self) -> usize {
        self.path_depths.iter().copied().max().unwrap_or(0) as usize
    }

    pub fn lazy_path_index_enabled(&self) -> bool {
        self.path_index_by_path.get().is_none()
    }

    pub fn path_index_for(&self, path: &Path) -> Option<usize> {
        let index = self.path_index_by_path.get_or_init(|| {
            self.files
                .iter()
                .cloned()
                .enumerate()
                .map(|(idx, file)| (file, idx))
                .collect()
        });
        index.get(path).copied()
    }

    fn ensure_compatible(&self, config: &SearchConfig) -> Result<()> {
        if self.roots.as_ref() != config.roots.as_slice() {
            bail!("prepared search targets were built for a different root set");
        }
        if self.options != search_options(config) {
            bail!("prepared search targets were built with different discovery options");
        }
        Ok(())
    }

    fn from_discovery(
        roots: Vec<PathBuf>,
        options: PreparedSearchOptions,
        discovery: DiscoveryResult,
    ) -> Self {
        let path_depths = discovery
            .files
            .iter()
            .map(|path| path_component_depth(path))
            .collect::<Vec<_>>();
        Self {
            roots: Arc::from(roots),
            files: Arc::from(discovery.files),
            path_depths: Arc::from(path_depths),
            path_index_by_path: Arc::new(OnceLock::new()),
            options,
            telemetry: discovery.telemetry,
            directory_root_count: discovery.directory_root_count,
            root_entry_count: discovery.root_entry_count,
        }
    }
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

pub fn prepare_search_targets(
    roots: Vec<PathBuf>,
    options: PreparedSearchOptions,
) -> Result<PreparedSearchTargets> {
    PreparedSearchTargets::discover(roots, options)
}

pub fn run_search(config: &SearchConfig) -> Result<SearchReport> {
    run_search_inner(config)
}

pub fn run_search_prepared(
    config: &SearchConfig,
    prepared_targets: &PreparedSearchTargets,
) -> Result<SearchReport> {
    let concurrency = ConcurrencyPlanner::detect();
    run_search_materialized_prepared(config, prepared_targets, concurrency)
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
    stats.set_linux_dominant_file_context(
        LINUX_DOMINANT_FILE_TARGET_CLASS,
        LINUX_DOMINANT_FILE_MIN_BYTES,
    );

    let run_plan = concurrency.plan_materialized(config.threads, discovery.files.len());
    stats.set_concurrency_context(
        run_plan.available_threads,
        run_plan.outer_scan_threads,
        run_plan.execution_mode.as_str(),
    );
    stats.observe_linux_strategy(linux_strategy_stats(
        LinuxStrategyInputs {
            matcher_strategy_supported: config.plan.supports_large_directory_streaming_selector(),
            effective_roots: stats.effective_roots,
            directory_roots: discovery.directory_root_count,
            root_entry_count: discovery.root_entry_count,
            files_discovered: discovery.files.len(),
            collect_hits: config.collect_hits,
            outer_parallel_shard_safe: config.plan.supports_outer_parallel_shard_fast_count(),
        },
        run_plan.execution_mode.as_str(),
    ));
    let scan_started = Instant::now();
    let fallback_line_profile = !config.collect_hits && fallback_line_profile_enabled();
    let mut outcomes = scan_paths(
        &discovery.files,
        &config.plan,
        config.collect_hits,
        config.max_hits,
        concurrency,
        run_plan.outer_scan_threads,
        fallback_line_profile,
    )?;
    stats.timings.scan_ms = scan_started.elapsed().as_secs_f64() * 1_000.0;

    let aggregate_started = Instant::now();
    let merge_started = Instant::now();
    for outcome in outcomes.drain(..) {
        merge_outcome(
            &mut stats,
            &mut hits,
            config.collect_hits,
            config.max_hits,
            Some(&discovery.files),
            outcome,
        );
    }
    stats.timings.aggregate_merge_ms = merge_started.elapsed().as_secs_f64() * 1_000.0;
    let finalize_started = Instant::now();
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
    stats.timings.aggregate_finalize_ms = finalize_started.elapsed().as_secs_f64() * 1_000.0;
    stats.timings.aggregate_ms = aggregate_started.elapsed().as_secs_f64() * 1_000.0;
    stats.timings.total_ms = total_started.elapsed().as_secs_f64() * 1_000.0;

    Ok(SearchReport {
        expression: config.plan.source.clone(),
        hits,
        stats,
    })
}

fn run_search_materialized_prepared(
    config: &SearchConfig,
    prepared_targets: &PreparedSearchTargets,
    concurrency: ConcurrencyPlanner,
) -> Result<SearchReport> {
    prepared_targets.ensure_compatible(config)?;

    let total_started = Instant::now();
    let mut stats = SearchStats::default();
    let mut hits = Vec::new();
    stats.timings.discover_ms = 0.0;
    stats.input_roots = prepared_targets.telemetry.input_roots;
    stats.effective_roots = prepared_targets.telemetry.effective_roots;
    stats.pruned_roots = prepared_targets.telemetry.pruned_roots;
    stats.overlap_pruned_roots = prepared_targets.telemetry.overlap_pruned_roots;
    stats.discovered_duplicate_paths = prepared_targets.telemetry.discovered_duplicate_paths;
    stats.files_discovered = prepared_targets.file_count();
    stats.set_linux_dominant_file_context(
        LINUX_DOMINANT_FILE_TARGET_CLASS,
        LINUX_DOMINANT_FILE_MIN_BYTES,
    );

    let run_plan =
        concurrency.plan_materialized_prepared(config.threads, prepared_targets.file_count());
    stats.set_concurrency_context(
        run_plan.available_threads,
        run_plan.outer_scan_threads,
        run_plan.execution_mode.as_str(),
    );
    stats.observe_linux_strategy(linux_strategy_stats(
        LinuxStrategyInputs {
            matcher_strategy_supported: config.plan.supports_large_directory_streaming_selector(),
            effective_roots: stats.effective_roots,
            directory_roots: prepared_targets.directory_root_count,
            root_entry_count: prepared_targets.root_entry_count,
            files_discovered: prepared_targets.file_count(),
            collect_hits: config.collect_hits,
            outer_parallel_shard_safe: config.plan.supports_outer_parallel_shard_fast_count(),
        },
        run_plan.execution_mode.as_str(),
    ));
    let scan_started = Instant::now();
    let fallback_line_profile = !config.collect_hits && fallback_line_profile_enabled();
    let mut outcomes = scan_paths(
        prepared_targets.files(),
        &config.plan,
        config.collect_hits,
        config.max_hits,
        concurrency,
        run_plan.outer_scan_threads,
        fallback_line_profile,
    )?;
    stats.timings.scan_ms = scan_started.elapsed().as_secs_f64() * 1_000.0;

    let aggregate_started = Instant::now();
    let merge_started = Instant::now();
    for outcome in outcomes.drain(..) {
        merge_outcome(
            &mut stats,
            &mut hits,
            config.collect_hits,
            config.max_hits,
            Some(prepared_targets.files()),
            outcome,
        );
    }
    stats.timings.aggregate_merge_ms = merge_started.elapsed().as_secs_f64() * 1_000.0;
    let finalize_started = Instant::now();
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
    stats.timings.aggregate_finalize_ms = finalize_started.elapsed().as_secs_f64() * 1_000.0;
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
    discover_files_with_options(search_options(config), roots)
}

fn discover_files_from_targets(
    config: &SearchConfig,
    roots: RootTargets,
) -> Result<DiscoveryResult> {
    discover_files_with_options(search_options(config), roots)
}

fn discover_files_with_options(
    options: PreparedSearchOptions,
    roots: RootTargets,
) -> Result<DiscoveryResult> {
    if roots.directory_roots.is_empty() {
        let files =
            finalize_discovered_files(roots.direct_files, roots.telemetry.effective_roots > 1);
        return Ok(DiscoveryResult {
            files: files.files,
            directory_root_count: roots.directory_roots.len(),
            root_entry_count: roots.root_entry_count,
            telemetry: DiscoveryTelemetry {
                discovered_duplicate_paths: files.duplicate_paths,
                ..roots.telemetry
            },
        });
    }

    let needs_dedupe = roots.telemetry.effective_roots > 1;
    let mut files = roots.direct_files;
    files.extend(discover_files_parallel(options, &roots.directory_roots)?);
    let files = finalize_discovered_files(files, needs_dedupe);
    Ok(DiscoveryResult {
        files: files.files,
        directory_root_count: roots.directory_roots.len(),
        root_entry_count: roots.root_entry_count,
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

fn build_walk_builder(options: PreparedSearchOptions, roots: &[PathBuf]) -> WalkBuilder {
    let mut builder = WalkBuilder::new(&roots[0]);
    for root in roots.iter().skip(1) {
        builder.add(root);
    }
    builder
        .hidden(!options.include_hidden)
        .follow_links(options.follow_symlinks)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .parents(true);
    builder
}

fn discover_files_parallel(
    options: PreparedSearchOptions,
    roots: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let builder = build_walk_builder(options, roots);
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
    root_entry_count: usize,
    telemetry: DiscoveryTelemetry,
}

fn partition_roots(config: &SearchConfig) -> RootTargets {
    partition_root_paths(&config.roots)
}

fn partition_root_paths(roots: &[PathBuf]) -> RootTargets {
    let normalized = normalize_roots(roots);
    let mut direct_files = Vec::new();
    let mut directory_roots = Vec::new();

    for root in &normalized.roots {
        match root.kind {
            RootKind::File => direct_files.push(root.path.clone()),
            RootKind::Directory => directory_roots.push(root.path.clone()),
        }
    }

    let root_entry_count = if normalized.roots.len() == 1 && directory_roots.len() == 1 {
        count_root_entries(&directory_roots[0])
    } else {
        0
    };

    RootTargets {
        direct_files,
        directory_roots,
        root_entry_count,
        telemetry: DiscoveryTelemetry {
            input_roots: roots.len(),
            effective_roots: normalized.roots.len(),
            pruned_roots: roots.len().saturating_sub(normalized.roots.len()),
            overlap_pruned_roots: normalized.overlap_pruned_roots,
            discovered_duplicate_paths: 0,
        },
    }
}

fn search_options(config: &SearchConfig) -> PreparedSearchOptions {
    PreparedSearchOptions {
        include_hidden: config.include_hidden,
        follow_symlinks: config.follow_symlinks,
    }
}

fn path_component_depth(path: &Path) -> u16 {
    path.components().count().min(u16::MAX as usize) as u16
}

fn count_root_entries(root: &Path) -> usize {
    std::fs::read_dir(root)
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0)
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

fn is_linux_dominant_file_target(path: &Path, bytes: u64) -> bool {
    if bytes < LINUX_DOMINANT_FILE_MIN_BYTES {
        return false;
    }

    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| !extension.eq_ignore_ascii_case("h"))
        .unwrap_or(true)
    {
        return false;
    }

    path_contains_component_sequence(path, &LINUX_DOMINANT_FILE_COMPONENTS)
}

fn path_contains_component_sequence(path: &Path, sequence: &[&str]) -> bool {
    if sequence.is_empty() {
        return true;
    }

    let components: Vec<String> = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();

    components.windows(sequence.len()).any(|window| {
        window
            .iter()
            .zip(sequence.iter())
            .all(|(actual, expected)| actual == expected)
    })
}

fn linux_dominant_file_gate(
    path: &Path,
    plan: &ExpressionPlan,
    collect_hits: bool,
    outer_scan_threads: usize,
    bytes: u64,
) -> bool {
    !collect_hits
        && outer_scan_threads <= 1
        && plan.supports_byte_mode()
        && is_linux_dominant_file_target(path, bytes)
        && (!plan.supports_parallel_fast_count_ranges()
            || !plan.supports_outer_parallel_shard_fast_count())
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
    let fallback_line_profile = fallback_line_profile_enabled();
    let streaming = scan_paths_streaming_stats_only(
        config,
        &roots,
        concurrency,
        run_plan.outer_scan_threads,
        fallback_line_profile,
    )?;

    stats.input_roots = roots.telemetry.input_roots;
    stats.effective_roots = roots.telemetry.effective_roots;
    stats.pruned_roots = roots.telemetry.pruned_roots;
    stats.overlap_pruned_roots = roots.telemetry.overlap_pruned_roots;
    stats.discovered_duplicate_paths = streaming.duplicate_paths;
    stats.files_discovered = streaming.files_discovered;
    stats.timings.discover_ms = streaming.discover_ms;
    stats.timings.scan_ms = streaming.scan_ms;
    stats.set_linux_dominant_file_context(
        LINUX_DOMINANT_FILE_TARGET_CLASS,
        LINUX_DOMINANT_FILE_MIN_BYTES,
    );
    stats.set_concurrency_context(
        run_plan.available_threads,
        run_plan.outer_scan_threads,
        run_plan.execution_mode.as_str(),
    );
    stats.observe_linux_strategy(linux_strategy_stats(
        LinuxStrategyInputs {
            matcher_strategy_supported: config.plan.supports_large_directory_streaming_selector(),
            effective_roots: roots.telemetry.effective_roots,
            directory_roots: roots.directory_roots.len(),
            root_entry_count: roots.root_entry_count,
            files_discovered: streaming.files_discovered,
            collect_hits: config.collect_hits,
            outer_parallel_shard_safe: config.plan.supports_outer_parallel_shard_fast_count(),
        },
        run_plan.execution_mode.as_str(),
    ));

    let aggregate_started = Instant::now();
    let merge_started = Instant::now();
    let mut ignored_hits = Vec::new();
    for outcome in streaming.outcomes {
        merge_outcome(&mut stats, &mut ignored_hits, false, None, None, outcome);
    }
    stats.timings.aggregate_merge_ms = merge_started.elapsed().as_secs_f64() * 1_000.0;
    let finalize_started = Instant::now();
    stats.timings.aggregate_finalize_ms = finalize_started.elapsed().as_secs_f64() * 1_000.0;
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
    fallback_line_profile: bool,
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
                        fallback_line_profile,
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
    let builder = build_walk_builder(search_options(config), roots);
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
    fallback_line_profile: bool,
) {
    loop {
        let path = match receiver.recv() {
            Ok(path) => path,
            Err(_) => break,
        };
        if sender
            .send(scan_file(
                &path,
                None,
                true,
                plan.as_ref(),
                false,
                None,
                concurrency,
                resolved_threads,
                fallback_line_profile,
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
    hit_limit: Option<usize>,
    concurrency: ConcurrencyPlanner,
    resolved_threads: usize,
    fallback_line_profile: bool,
) -> Result<Vec<FileScanOutcome>> {
    if resolved_threads <= 1 {
        return Ok(files
            .iter()
            .enumerate()
            .map(|(path_index, path)| {
                scan_file(
                    path,
                    Some(path_index),
                    false,
                    plan,
                    collect_hits,
                    hit_limit,
                    concurrency,
                    resolved_threads,
                    fallback_line_profile,
                )
            })
            .collect());
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(resolved_threads)
        .build()
        .context("failed to configure rayon thread pool")?;
    Ok(pool.install(|| {
        files
            .par_iter()
            .enumerate()
            .map(|(path_index, path)| {
                scan_file(
                    path,
                    Some(path_index),
                    false,
                    plan,
                    collect_hits,
                    hit_limit,
                    concurrency,
                    resolved_threads,
                    fallback_line_profile,
                )
            })
            .collect()
    }))
}

fn merge_outcome(
    stats: &mut SearchStats,
    hits: &mut Vec<SearchHit>,
    collect_hits: bool,
    hit_limit: Option<usize>,
    materialized_paths: Option<&[PathBuf]>,
    outcome: FileScanOutcome,
) {
    if outcome.scanned {
        let outcome_path = outcome_path(&outcome, materialized_paths);
        stats.files_scanned += 1;
        stats.bytes_scanned += outcome.bytes;
        stats.observe_scan_work(outcome.duration_ms);
        stats.acceleration_bailouts += outcome.acceleration_bailouts;
        stats.observe_regex_decomposition(outcome.regex_decomposition);
        stats.observe_unicode_casefold_prefilter(outcome.unicode_casefold_prefilter);
        stats.observe_fast_count_density(outcome.fast_count_density);
        stats.observe_byte_shard_kernel(outcome.byte_shard_kernel);
        stats.observe_linux_dominant_file_sample(outcome.linux_dominant_target, outcome.bytes);
        stats.observe_linux_dominant_file_execution(
            outcome.linux_dominant_file.eligible,
            outcome.linux_dominant_file.activated,
            outcome.linux_dominant_file.bailed_out,
            outcome.linux_dominant_file.shard_threads,
            outcome.linux_dominant_file.range_count,
            outcome.linux_dominant_file.chunk_bytes,
        );
        stats.consider_slow_file(
            outcome_path,
            outcome.duration_ms,
            outcome.bytes,
            outcome.linux_dominant_target,
        );
        stats.observe_fallback_line_scan(outcome.fallback_line_scan.map(|telemetry| *telemetry));
        stats.matches_found += outcome.match_count;
        if let Some(shard_plan) = outcome.shard_plan {
            stats.observe_parallel_sharding(
                shard_plan.shard_threads,
                shard_plan.range_count,
                shard_plan.chunk_bytes,
            );
            stats.observe_fast_count_density(FastCountDensityStats {
                shard_merge_calls: 1,
                shard_merge_ranges: shard_plan.range_count,
                shard_merge_matches: outcome.match_count,
                ..FastCountDensityStats::default()
            });
        }
        if collect_hits {
            merge_hits(hits, outcome.hits, hit_limit);
        }
    } else {
        stats.files_skipped += 1;
    }
}

fn outcome_path<'a>(
    outcome: &'a FileScanOutcome,
    materialized_paths: Option<&'a [PathBuf]>,
) -> &'a Path {
    if let Some(path_index) = outcome.path_index {
        return materialized_paths
            .and_then(|paths| paths.get(path_index))
            .map(PathBuf::as_path)
            .expect("materialized FileScanOutcome path index must resolve");
    }

    outcome
        .path
        .as_deref()
        .expect("streaming FileScanOutcome must carry owned path")
}

fn merge_hits(hits: &mut Vec<SearchHit>, incoming: Vec<SearchHit>, hit_limit: Option<usize>) {
    match hit_limit {
        Some(0) => {}
        Some(limit) => {
            hits.extend(incoming);
            if hits.len() > limit {
                let _ = hits.select_nth_unstable_by(limit, compare_hits);
                hits.truncate(limit);
            }
        }
        None => hits.extend(incoming),
    }
}

fn compare_hits(left: &SearchHit, right: &SearchHit) -> CmpOrdering {
    left.path
        .cmp(&right.path)
        .then(left.line.cmp(&right.line))
        .then(left.column.cmp(&right.column))
}

fn scan_file(
    path: &Path,
    path_index: Option<usize>,
    own_path: bool,
    plan: &ExpressionPlan,
    collect_hits: bool,
    hit_limit: Option<usize>,
    concurrency: ConcurrencyPlanner,
    outer_scan_threads: usize,
    fallback_line_profile: bool,
) -> FileScanOutcome {
    let started = Instant::now();
    let mut outcome = {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(_) => return failed_outcome(path, path_index, own_path, 0),
        };

        let mut tiny = [0u8; TINY_FILE_INLINE_LIMIT];
        let tiny_read = match file.read(&mut tiny) {
            Ok(read) => read,
            Err(_) => return failed_outcome(path, path_index, own_path, 0),
        };

        if tiny_read < TINY_FILE_INLINE_LIMIT {
            scan_loaded_bytes(
                path,
                path_index,
                own_path,
                plan,
                collect_hits,
                hit_limit,
                concurrency,
                outer_scan_threads,
                fallback_line_profile,
                &tiny[..tiny_read],
                tiny_read as u64,
            )
        } else {
            let mut sentinel = [0u8; 1];
            let sentinel_read = match file.read(&mut sentinel) {
                Ok(read) => read,
                Err(_) => return failed_outcome(path, path_index, own_path, tiny_read as u64),
            };

            if sentinel_read == 0 {
                scan_loaded_bytes(
                    path,
                    path_index,
                    own_path,
                    plan,
                    collect_hits,
                    hit_limit,
                    concurrency,
                    outer_scan_threads,
                    fallback_line_profile,
                    &tiny,
                    tiny.len() as u64,
                )
            } else {
                let metadata = match file.metadata() {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        return failed_outcome(
                            path,
                            path_index,
                            own_path,
                            (tiny_read + sentinel_read) as u64,
                        )
                    }
                };

                if metadata.len() <= SMALL_FILE_INLINE_LIMIT {
                    let mut bytes = Vec::with_capacity(metadata.len() as usize);
                    bytes.extend_from_slice(&tiny);
                    bytes.push(sentinel[0]);
                    if file.read_to_end(&mut bytes).is_err() {
                        return failed_outcome(path, path_index, own_path, metadata.len());
                    }
                    scan_loaded_bytes(
                        path,
                        path_index,
                        own_path,
                        plan,
                        collect_hits,
                        hit_limit,
                        concurrency,
                        outer_scan_threads,
                        fallback_line_profile,
                        &bytes,
                        metadata.len(),
                    )
                } else {
                    let mmap = match unsafe { MmapOptions::new().map(&file) } {
                        Ok(mmap) => mmap,
                        Err(_) => {
                            return failed_outcome(path, path_index, own_path, metadata.len())
                        }
                    };
                    scan_loaded_bytes(
                        path,
                        path_index,
                        own_path,
                        plan,
                        collect_hits,
                        hit_limit,
                        concurrency,
                        outer_scan_threads,
                        fallback_line_profile,
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
    path_index: Option<usize>,
    own_path: bool,
    plan: &ExpressionPlan,
    collect_hits: bool,
    hit_limit: Option<usize>,
    concurrency: ConcurrencyPlanner,
    outer_scan_threads: usize,
    fallback_line_profile: bool,
    bytes: &[u8],
    file_bytes: u64,
) -> FileScanOutcome {
    if is_likely_binary(bytes) {
        return failed_outcome(path, path_index, own_path, file_bytes);
    }

    let mut hits = Vec::new();
    let mut match_count = 0usize;
    let mut acceleration_bailouts = 0usize;
    let mut regex_decomposition = RegexDecompositionStats::default();
    let mut unicode_casefold_prefilter = UnicodeCaseFoldPrefilterStats::default();
    let mut fast_count_density = FastCountDensityStats::default();
    let mut byte_shard_kernel = ByteShardKernelStats::default();
    let mut fallback_line_scan = None::<Box<FallbackLineScanStats>>;
    let mut linux_dominant_file = LinuxDominantFileExecution {
        eligible: linux_dominant_file_gate(
            path,
            plan,
            collect_hits,
            outer_scan_threads,
            file_bytes,
        ),
        ..LinuxDominantFileExecution::default()
    };
    let mut cached_path = None::<String>;

    if !collect_hits {
        if linux_dominant_file.eligible {
            if let Some((fast_count, shard_plan, shard_kernel)) =
                maybe_linux_dominant_file_fast_count_bytes(
                    plan,
                    bytes,
                    concurrency,
                    outer_scan_threads,
                )
            {
                match_count = fast_count.count;
                unicode_casefold_prefilter = fast_count.unicode_casefold_prefilter;
                fast_count_density = fast_count.fast_count_density;
                byte_shard_kernel = shard_kernel;
                linux_dominant_file.activated = true;
                linux_dominant_file.shard_threads = shard_plan.shard_threads;
                linux_dominant_file.range_count = shard_plan.range_count;
                linux_dominant_file.chunk_bytes = shard_plan.chunk_bytes;
                return completed_outcome(
                    path,
                    path_index,
                    own_path,
                    file_bytes,
                    hits,
                    match_count,
                    acceleration_bailouts,
                    regex_decomposition,
                    unicode_casefold_prefilter,
                    fast_count_density,
                    byte_shard_kernel,
                    fallback_line_scan,
                    Some(shard_plan),
                    linux_dominant_file,
                );
            }
            linux_dominant_file.bailed_out = true;
        }
        let skip_parallel_fast_count = outer_scan_threads > 1
            && plan.uses_single_literal_counter()
            && is_linux_dominant_file_target(path, file_bytes);
        if !skip_parallel_fast_count {
            if let Some((fast_count, shard_plan, shard_kernel)) =
                maybe_parallel_fast_count_bytes(plan, bytes, concurrency, outer_scan_threads)
            {
                match_count = fast_count.count;
                unicode_casefold_prefilter = fast_count.unicode_casefold_prefilter;
                fast_count_density = fast_count.fast_count_density;
                byte_shard_kernel = shard_kernel;
                return completed_outcome(
                    path,
                    path_index,
                    own_path,
                    file_bytes,
                    hits,
                    match_count,
                    acceleration_bailouts,
                    regex_decomposition,
                    unicode_casefold_prefilter,
                    fast_count_density,
                    byte_shard_kernel,
                    fallback_line_scan,
                    Some(shard_plan),
                    linux_dominant_file,
                );
            }
        }
        let decomposition_result = if let Some((result, shard_plan)) =
            maybe_parallel_regex_decomposition_count_bytes(
                plan,
                bytes,
                concurrency,
                outer_scan_threads,
            ) {
            Some((result, Some(shard_plan)))
        } else {
            plan.fast_decomposition_count_no_hits_bytes(bytes)
                .map(|result| (result, None))
        };

        match decomposition_result {
            Some((FastDecompositionResult::Count(counts), shard_plan)) => {
                match_count = counts.match_count;
                regex_decomposition = counts.telemetry(true, false);
                return completed_outcome(
                    path,
                    path_index,
                    own_path,
                    file_bytes,
                    hits,
                    match_count,
                    acceleration_bailouts,
                    regex_decomposition,
                    unicode_casefold_prefilter,
                    fast_count_density,
                    byte_shard_kernel,
                    fallback_line_scan,
                    shard_plan,
                    linux_dominant_file,
                );
            }
            Some((FastDecompositionResult::Bailout(counts), _)) => {
                acceleration_bailouts += 1;
                regex_decomposition = counts.telemetry(false, true);
            }
            None => {}
        }
        let fast_count_result = if fallback_line_profile {
            count_fast_match_bytes_with_profile(plan, path, bytes, file_bytes)
                .map(|profiled| (profiled.outcome, Some(Box::new(profiled.telemetry))))
        } else {
            plan.fast_match_count_no_hits_bytes_with_stats(bytes)
                .map(|outcome| (outcome, None))
        };
        if let Some((fast_count, telemetry)) = fast_count_result {
            match_count = fast_count.count;
            unicode_casefold_prefilter = fast_count.unicode_casefold_prefilter;
            fast_count_density = fast_count.fast_count_density;
            if telemetry.is_some() {
                fallback_line_scan = telemetry;
            }
            return completed_outcome(
                path,
                path_index,
                own_path,
                file_bytes,
                hits,
                match_count,
                acceleration_bailouts,
                regex_decomposition,
                unicode_casefold_prefilter,
                fast_count_density,
                byte_shard_kernel,
                fallback_line_scan,
                None,
                linux_dominant_file,
            );
        }
    }

    if plan.supports_byte_mode() {
        if fallback_line_profile {
            let profiled = count_fallback_byte_lines_with_profile(plan, path, bytes, file_bytes);
            match_count = profiled.match_count;
            fallback_line_scan = Some(Box::new(profiled.telemetry));
        } else {
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
                    if should_retain_hit(collect_hits, hits.len(), hit_limit) {
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
        }
    } else {
        let text = String::from_utf8_lossy(bytes);
        if !collect_hits {
            if let Some(count) = plan.fast_match_count_no_hits(&text) {
                match_count = count;
                return completed_outcome(
                    path,
                    path_index,
                    own_path,
                    file_bytes,
                    hits,
                    match_count,
                    acceleration_bailouts,
                    regex_decomposition,
                    unicode_casefold_prefilter,
                    fast_count_density,
                    byte_shard_kernel,
                    fallback_line_scan,
                    None,
                    linux_dominant_file,
                );
            }
        }

        for (line_idx, line) in text.lines().enumerate() {
            if !plan.matches(line) {
                continue;
            }
            match_count += 1;
            if should_retain_hit(collect_hits, hits.len(), hit_limit) {
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

    completed_outcome(
        path,
        path_index,
        own_path,
        file_bytes,
        hits,
        match_count,
        acceleration_bailouts,
        regex_decomposition,
        unicode_casefold_prefilter,
        fast_count_density,
        byte_shard_kernel,
        fallback_line_scan,
        None,
        linux_dominant_file,
    )
}

#[derive(Debug)]
struct FallbackLineProfileResult {
    match_count: usize,
    telemetry: FallbackLineScanStats,
}

#[derive(Debug)]
struct FallbackFastCountProfileResult {
    outcome: FastCountOutcome,
    telemetry: FallbackLineScanStats,
}

fn count_fast_match_bytes_with_profile(
    plan: &ExpressionPlan,
    path: &Path,
    bytes: &[u8],
    file_bytes: u64,
) -> Option<FallbackFastCountProfileResult> {
    let mut telemetry = FallbackLineScanStats {
        enabled: true,
        files_profiled: 1,
        scanned_line_bytes: bytes.len(),
        max_file_bytes: file_bytes,
        max_file_path: path.display().to_string(),
        ..FallbackLineScanStats::default()
    };

    let newline_started = Instant::now();
    let mut line_start = 0usize;
    loop {
        if line_start == bytes.len() {
            break;
        }

        let line_end = match memchr(b'\n', &bytes[line_start..]) {
            Some(offset) => line_start + offset,
            None => bytes.len(),
        };
        let line = trim_trailing_cr(&bytes[line_start..line_end]);
        telemetry.line_count += 1;
        telemetry.max_line_bytes = telemetry.max_line_bytes.max(line.len());

        if line_end == bytes.len() {
            break;
        }
        line_start = line_end + 1;
    }
    telemetry.newline_elapsed_ns_total = duration_ns_u64(newline_started.elapsed());

    let regex_started = Instant::now();
    let outcome = plan.fast_match_count_no_hits_bytes_with_stats(bytes)?;
    telemetry.regex_elapsed_ns_total = duration_ns_u64(regex_started.elapsed());
    telemetry.candidate_lines = telemetry.line_count;
    telemetry.matched_lines = outcome.count;
    telemetry.max_file_elapsed_ns =
        telemetry.newline_elapsed_ns_total + telemetry.regex_elapsed_ns_total;
    telemetry.max_file_lines = telemetry.line_count;
    telemetry.max_file_matches = outcome.count;

    Some(FallbackFastCountProfileResult { outcome, telemetry })
}

fn count_fallback_byte_lines_with_profile(
    plan: &ExpressionPlan,
    path: &Path,
    bytes: &[u8],
    file_bytes: u64,
) -> FallbackLineProfileResult {
    let file_started = Instant::now();
    let mut line_start = 0usize;
    let mut match_count = 0usize;
    let mut telemetry = FallbackLineScanStats {
        enabled: true,
        files_profiled: 1,
        max_file_bytes: file_bytes,
        max_file_path: path.display().to_string(),
        ..FallbackLineScanStats::default()
    };

    loop {
        if line_start == bytes.len() {
            break;
        }

        let newline_started = Instant::now();
        let line_end = match memchr(b'\n', &bytes[line_start..]) {
            Some(offset) => line_start + offset,
            None => bytes.len(),
        };
        telemetry.newline_elapsed_ns_total += duration_ns_u64(newline_started.elapsed());

        let raw_line = &bytes[line_start..line_end];
        let line = trim_trailing_cr(raw_line);
        telemetry.line_count += 1;
        telemetry.candidate_lines += 1;
        telemetry.scanned_line_bytes += line.len();
        telemetry.max_line_bytes = telemetry.max_line_bytes.max(line.len());

        let regex_started = Instant::now();
        let matched = plan.matches_bytes(line);
        telemetry.regex_elapsed_ns_total += duration_ns_u64(regex_started.elapsed());
        if matched {
            match_count += 1;
            telemetry.matched_lines += 1;
        }

        if line_end == bytes.len() {
            break;
        }
        line_start = line_end + 1;
    }

    telemetry.max_file_elapsed_ns = duration_ns_u64(file_started.elapsed());
    telemetry.max_file_lines = telemetry.line_count;
    telemetry.max_file_matches = match_count;

    FallbackLineProfileResult {
        match_count,
        telemetry,
    }
}

fn should_retain_hit(collect_hits: bool, retained_hits: usize, hit_limit: Option<usize>) -> bool {
    collect_hits
        && match hit_limit {
            Some(limit) => retained_hits < limit,
            None => true,
        }
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
) -> Option<(FastCountOutcome, ParallelShardPlan, ByteShardKernelStats)> {
    if outer_scan_threads > 1 && !plan.supports_outer_parallel_shard_fast_count() {
        return None;
    }
    let shard_plan = concurrency.plan_parallel_fast_count(
        bytes.len(),
        outer_scan_threads,
        plan.uses_single_literal_counter(),
    )?;
    let ranges = build_chunk_ranges(bytes.len(), shard_plan.chunk_bytes);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(shard_plan.shard_threads)
        .build()
        .ok()?;
    let profile_kernel = byte_shard_kernel_profile_enabled();
    pool.install(|| {
        ranges
            .par_iter()
            .map(|(start, end)| {
                count_fast_range_with_optional_profile(plan, bytes, *start, *end, profile_kernel)
            })
            .collect::<Option<Vec<_>>>()
            .map(|counts| merge_shard_range_counts(counts, shard_plan, profile_kernel))
    })
}

fn maybe_parallel_regex_decomposition_count_bytes(
    plan: &ExpressionPlan,
    bytes: &[u8],
    concurrency: ConcurrencyPlanner,
    outer_scan_threads: usize,
) -> Option<(FastDecompositionResult, ParallelShardPlan)> {
    let shard_plan = regex_decomposition_parallel_plan_with_available(
        bytes.len(),
        outer_scan_threads,
        concurrency.available_threads,
    )?;
    let ranges = build_chunk_ranges(bytes.len(), shard_plan.chunk_bytes);
    plan.fast_decomposition_count_no_hits_bytes_sharded(bytes, &ranges)
        .map(|result| (result, shard_plan))
}

fn byte_shard_kernel_profile_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("IX_BYTE_SHARD_KERNEL_PROFILE")
            .and_then(|value| value.into_string().ok())
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

fn fallback_line_profile_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("IX_FALLBACK_LINE_PROFILE")
            .and_then(|value| value.into_string().ok())
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

fn count_fast_range_with_optional_profile(
    plan: &ExpressionPlan,
    bytes: &[u8],
    start: usize,
    end: usize,
    profile_kernel: bool,
) -> Option<ShardRangeCount> {
    if !profile_kernel {
        return plan
            .fast_match_count_no_hits_bytes_in_range_with_stats(bytes, start, end)
            .map(|outcome| ShardRangeCount {
                outcome,
                kernel: ByteShardKernelStats::default(),
            });
    }

    let overlap = plan.fast_match_count_range_overlap().unwrap_or(0);
    let logical_range_bytes = end.saturating_sub(start.min(end));
    let slice_start = start.saturating_sub(overlap);
    let slice_end = bytes.len().min(end.saturating_add(overlap));
    let widened_range_bytes = slice_end.saturating_sub(slice_start);
    let started = Instant::now();
    let outcome = plan.fast_match_count_no_hits_bytes_in_range_with_stats(bytes, start, end)?;
    let elapsed_ns = duration_ns_u64(started.elapsed());

    Some(ShardRangeCount {
        kernel: ByteShardKernelStats {
            enabled: true,
            range_calls: 1,
            logical_range_bytes,
            widened_range_bytes,
            overlap_bytes: widened_range_bytes.saturating_sub(logical_range_bytes),
            range_elapsed_ns_total: elapsed_ns,
            max_range_elapsed_ns: elapsed_ns,
            matches: outcome.count,
            ..ByteShardKernelStats::default()
        },
        outcome,
    })
}

fn merge_shard_range_counts(
    counts: Vec<ShardRangeCount>,
    shard_plan: ParallelShardPlan,
    profile_kernel: bool,
) -> (FastCountOutcome, ParallelShardPlan, ByteShardKernelStats) {
    let reduce_started = profile_kernel.then(Instant::now);
    let mut merged = FastCountOutcome::default();
    let mut kernel = ByteShardKernelStats {
        enabled: profile_kernel,
        files_profiled: usize::from(profile_kernel),
        ..ByteShardKernelStats::default()
    };

    for count in counts {
        merged.count += count.outcome.count;
        merged.fast_count_density.literal_range_calls +=
            count.outcome.fast_count_density.literal_range_calls;
        merged.fast_count_density.literal_range_bytes +=
            count.outcome.fast_count_density.literal_range_bytes;
        merged.fast_count_density.literal_matches +=
            count.outcome.fast_count_density.literal_matches;
        merged.fast_count_density.alternate_range_calls +=
            count.outcome.fast_count_density.alternate_range_calls;
        merged.fast_count_density.alternate_range_bytes +=
            count.outcome.fast_count_density.alternate_range_bytes;
        merged.fast_count_density.alternate_matches +=
            count.outcome.fast_count_density.alternate_matches;
        merged.unicode_casefold_prefilter = merge_unicode_casefold_prefilter_stats(
            merged.unicode_casefold_prefilter,
            count.outcome,
        );

        kernel.range_calls += count.kernel.range_calls;
        kernel.logical_range_bytes += count.kernel.logical_range_bytes;
        kernel.widened_range_bytes += count.kernel.widened_range_bytes;
        kernel.overlap_bytes += count.kernel.overlap_bytes;
        kernel.range_elapsed_ns_total += count.kernel.range_elapsed_ns_total;
        kernel.max_range_elapsed_ns = kernel
            .max_range_elapsed_ns
            .max(count.kernel.max_range_elapsed_ns);
        kernel.matches += count.kernel.matches;
    }

    if let Some(started) = reduce_started {
        let elapsed_ns = duration_ns_u64(started.elapsed());
        kernel.reduce_elapsed_ns_total = elapsed_ns;
        kernel.max_reduce_elapsed_ns = elapsed_ns;
    }

    (merged, shard_plan, kernel)
}

fn merge_unicode_casefold_prefilter_stats(
    mut telemetry: UnicodeCaseFoldPrefilterStats,
    count: FastCountOutcome,
) -> UnicodeCaseFoldPrefilterStats {
    telemetry.full_scan_calls += count.unicode_casefold_prefilter.full_scan_calls;
    telemetry.range_scan_calls += count.unicode_casefold_prefilter.range_scan_calls;
    telemetry.candidate_prefix_hits += count.unicode_casefold_prefilter.candidate_prefix_hits;
    telemetry.candidate_windows_verified +=
        count.unicode_casefold_prefilter.candidate_windows_verified;
    telemetry.confirmed_matches += count.unicode_casefold_prefilter.confirmed_matches;
    telemetry.rejected_candidates += count.unicode_casefold_prefilter.rejected_candidates;
    telemetry.candidate_gap_bytes_total +=
        count.unicode_casefold_prefilter.candidate_gap_bytes_total;
    telemetry.candidate_gap_samples += count.unicode_casefold_prefilter.candidate_gap_samples;
    telemetry.max_prefix_variant_count = telemetry
        .max_prefix_variant_count
        .max(count.unicode_casefold_prefilter.max_prefix_variant_count);
    telemetry.max_prefix_len = telemetry
        .max_prefix_len
        .max(count.unicode_casefold_prefilter.max_prefix_len);
    telemetry.max_match_len = telemetry
        .max_match_len
        .max(count.unicode_casefold_prefilter.max_match_len);
    telemetry
}

fn duration_ns_u64(duration: std::time::Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

fn regex_decomposition_parallel_plan_with_available(
    file_len: usize,
    outer_scan_threads: usize,
    available: usize,
) -> Option<ParallelShardPlan> {
    if file_len < REGEX_DECOMPOSITION_PARALLEL_FILE_THRESHOLD || outer_scan_threads > 1 {
        return None;
    }

    let shard_budget = threads_90pct(available.max(1));
    let shard_threads = shard_budget.min(REGEX_DECOMPOSITION_PARALLEL_MAX_SHARD_THREADS);
    if shard_threads <= 1 {
        return None;
    }

    let range_count = shard_threads;
    let chunk_bytes = file_len.div_ceil(range_count);
    Some(ParallelShardPlan {
        shard_threads,
        chunk_bytes,
        range_count,
    })
}

fn linux_dominant_file_fast_count_with_available(
    plan: &ExpressionPlan,
    bytes: &[u8],
    outer_scan_threads: usize,
    available: usize,
) -> Option<(FastCountOutcome, ParallelShardPlan, ByteShardKernelStats)> {
    if !plan.supports_parallel_fast_count_ranges() {
        return None;
    }

    let shard_plan = linux_dominant_file_parallel_plan_with_available(
        bytes.len(),
        outer_scan_threads,
        available,
    )?;
    let ranges = build_chunk_ranges(bytes.len(), shard_plan.chunk_bytes);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(shard_plan.shard_threads)
        .build()
        .ok()?;
    let profile_kernel = byte_shard_kernel_profile_enabled();
    pool.install(|| {
        ranges
            .par_iter()
            .map(|(start, end)| {
                count_fast_range_with_optional_profile(plan, bytes, *start, *end, profile_kernel)
            })
            .collect::<Option<Vec<_>>>()
            .map(|counts| merge_shard_range_counts(counts, shard_plan, profile_kernel))
    })
}

fn maybe_linux_dominant_file_fast_count_bytes(
    plan: &ExpressionPlan,
    bytes: &[u8],
    concurrency: ConcurrencyPlanner,
    outer_scan_threads: usize,
) -> Option<(FastCountOutcome, ParallelShardPlan, ByteShardKernelStats)> {
    linux_dominant_file_fast_count_with_available(
        plan,
        bytes,
        outer_scan_threads,
        concurrency.available_threads,
    )
}

fn linux_dominant_file_parallel_plan_with_available(
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

    if outer_scan_threads > 1 {
        return None;
    }

    let shard_headroom = threads_90pct(available);
    let shard_threads = shard_headroom.min(LINUX_DOMINANT_FILE_MAX_SHARD_THREADS);
    if shard_threads <= 1 {
        return None;
    }

    let min_chunk_bytes = parallel_fast_count_min_chunk_bytes(file_len);
    let max_range_count = file_len.div_ceil(min_chunk_bytes);
    if max_range_count <= 1 {
        return None;
    }

    let target_range_count = shard_threads
        .saturating_mul(LINUX_DOMINANT_FILE_TARGET_RANGES_PER_THREAD)
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
    dominant_literal_scan: bool,
) -> Option<ParallelShardPlan> {
    parallel_fast_count_plan_with_available(
        file_len,
        outer_scan_threads,
        available_threads(),
        dominant_literal_scan,
    )
}

fn parallel_fast_count_plan_with_available(
    file_len: usize,
    outer_scan_threads: usize,
    available: usize,
    dominant_literal_scan: bool,
) -> Option<ParallelShardPlan> {
    if file_len < PARALLEL_FAST_COUNT_FILE_THRESHOLD {
        return None;
    }

    let available = available.max(1);
    if available <= 1 {
        return None;
    }

    let shard_budget = parallel_fast_count_thread_budget_with_available(
        file_len,
        outer_scan_threads,
        available,
        dominant_literal_scan,
    )?;
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
    dominant_literal_scan: bool,
) -> Option<usize> {
    let shard_budget = threads_90pct(available.max(1));

    if outer_scan_threads <= 1 {
        if dominant_literal_scan && file_len >= DOMINANT_FILE_PARALLEL_THRESHOLD {
            let dominant_threads = shard_budget.min(dominant_parallel_thread_cap(shard_budget));
            return (dominant_threads > 1).then_some(dominant_threads);
        }

        return (shard_budget > 1).then_some(shard_budget);
    }

    if file_len < PARALLEL_FAST_COUNT_FILE_THRESHOLD {
        return None;
    }

    if file_len < DOMINANT_FILE_PARALLEL_THRESHOLD {
        let medium_thread_cap = if dominant_literal_scan {
            PARALLEL_FAST_COUNT_OUTER_LITERAL_MEDIUM_THREAD_CAP
        } else {
            3
        };
        let medium_threads = shard_budget.min(medium_thread_cap);
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
    path_index: Option<usize>,
    own_path: bool,
    bytes: u64,
    hits: Vec<SearchHit>,
    match_count: usize,
    acceleration_bailouts: usize,
    regex_decomposition: RegexDecompositionStats,
    unicode_casefold_prefilter: UnicodeCaseFoldPrefilterStats,
    fast_count_density: FastCountDensityStats,
    byte_shard_kernel: ByteShardKernelStats,
    fallback_line_scan: Option<Box<FallbackLineScanStats>>,
    shard_plan: Option<ParallelShardPlan>,
    linux_dominant_file: LinuxDominantFileExecution,
) -> FileScanOutcome {
    FileScanOutcome {
        path: own_path.then(|| path.to_path_buf()),
        path_index,
        duration_ms: 0.0,
        bytes,
        hits,
        match_count,
        acceleration_bailouts,
        regex_decomposition,
        unicode_casefold_prefilter,
        fast_count_density,
        byte_shard_kernel,
        fallback_line_scan,
        scanned: true,
        shard_plan,
        linux_dominant_target: is_linux_dominant_file_target(path, bytes),
        linux_dominant_file,
    }
}

fn failed_outcome(
    path: &Path,
    path_index: Option<usize>,
    own_path: bool,
    bytes: u64,
) -> FileScanOutcome {
    FileScanOutcome {
        path: own_path.then(|| path.to_path_buf()),
        path_index,
        duration_ms: 0.0,
        bytes,
        hits: Vec::new(),
        match_count: 0,
        acceleration_bailouts: 0,
        regex_decomposition: RegexDecompositionStats::default(),
        unicode_casefold_prefilter: UnicodeCaseFoldPrefilterStats::default(),
        fast_count_density: FastCountDensityStats::default(),
        byte_shard_kernel: ByteShardKernelStats::default(),
        fallback_line_scan: None,
        scanned: false,
        shard_plan: None,
        linux_dominant_target: false,
        linux_dominant_file: LinuxDominantFileExecution::default(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde_json::Value;

    use crate::ExpressionPlan;

    use super::{
        auto_threads_for_shape, auto_threads_for_shape_with_available,
        auto_threads_for_streaming_with_available, discover_files, dominant_parallel_thread_cap,
        is_linux_dominant_file_target, linux_dominant_file_gate,
        linux_dominant_file_parallel_plan_with_available, linux_strategy_prefers_streaming,
        linux_strategy_selector_eligible, linux_strategy_stats,
        parallel_fast_count_min_chunk_bytes, parallel_fast_count_plan_with_available,
        partition_roots, prefer_single_root_streaming_stats_only, prepare_search_targets,
        run_search, run_search_prepared, scan_loaded_bytes, should_stream_stats_only,
        threads_90pct, ConcurrencyPlanner, LinuxStrategyInputs, PreparedSearchOptions,
        SearchConfig, DOMINANT_FILE_PARALLEL_THREAD_CAP_MAX, DOMINANT_FILE_PARALLEL_THRESHOLD,
        LINUX_DOMINANT_FILE_MIN_BYTES, LINUX_STRATEGY_MIN_FILES, LINUX_STRATEGY_MIN_ROOT_ENTRIES,
        PARALLEL_FAST_COUNT_FILE_THRESHOLD, PARALLEL_FAST_COUNT_MEDIUM_MIN_CHUNK_BYTES,
        PARALLEL_FAST_COUNT_OUTER_LITERAL_MEDIUM_THREAD_CAP,
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
    fn auto_threads_for_shape_uses_90pct_available_threads_for_large_file_sets() {
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
            parallel_fast_count_plan_with_available(
                PARALLEL_FAST_COUNT_FILE_THRESHOLD - 1,
                1,
                32,
                false,
            ),
            None
        );
    }

    #[test]
    fn parallel_fast_count_plan_enables_single_threaded_large_files() {
        let file_len = PARALLEL_FAST_COUNT_FILE_THRESHOLD * 4;
        let shard_plan = parallel_fast_count_plan_with_available(file_len, 1, 32, false)
            .expect("large single-threaded files should parallelize");
        assert!(shard_plan.shard_threads > 1);
        assert!(shard_plan.range_count >= shard_plan.shard_threads);
        assert!(shard_plan.chunk_bytes >= PARALLEL_FAST_COUNT_MEDIUM_MIN_CHUNK_BYTES);
    }

    #[test]
    fn parallel_fast_count_plan_enables_giant_file_override_under_outer_parallelism() {
        let shard_plan = parallel_fast_count_plan_with_available(
            DOMINANT_FILE_PARALLEL_THRESHOLD,
            16,
            32,
            false,
        )
        .expect("dominant giant files should get an inner parallel override");
        assert!(shard_plan.shard_threads > 1);
        assert!(shard_plan.shard_threads <= DOMINANT_FILE_PARALLEL_THREAD_CAP_MAX);
        assert!(shard_plan.range_count >= shard_plan.shard_threads);
    }

    #[test]
    fn parallel_fast_count_plan_enables_outer_parallel_large_files_with_capped_budget() {
        let file_len = PARALLEL_FAST_COUNT_FILE_THRESHOLD * 4;
        let shard_plan = parallel_fast_count_plan_with_available(file_len, 8, 32, false)
            .expect("outer-parallel large files should receive a capped inner shard budget");
        assert_eq!(shard_plan.shard_threads, 3);
        assert!(shard_plan.range_count >= shard_plan.shard_threads);
    }

    #[test]
    fn parallel_fast_count_plan_caps_outer_parallel_literal_medium_files_more_aggressively() {
        let file_len = PARALLEL_FAST_COUNT_FILE_THRESHOLD * 4;
        let literal_plan = parallel_fast_count_plan_with_available(file_len, 8, 32, true)
            .expect("outer-parallel literal medium files should still shard");
        let non_literal_plan = parallel_fast_count_plan_with_available(file_len, 8, 32, false)
            .expect("outer-parallel non-literal medium files should keep baseline cap");

        assert_eq!(
            literal_plan.shard_threads,
            PARALLEL_FAST_COUNT_OUTER_LITERAL_MEDIUM_THREAD_CAP
        );
        assert_eq!(non_literal_plan.shard_threads, 3);
        assert!(literal_plan.range_count >= literal_plan.shard_threads);
    }

    #[test]
    fn parallel_fast_count_plan_feeds_threads_with_multiple_ranges_on_mid_size_files() {
        let file_len = 144 * 1024 * 1024;
        let shard_plan = parallel_fast_count_plan_with_available(file_len, 1, 32, false)
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
        let shard_plan = parallel_fast_count_plan_with_available(file_len, 8, 32, false)
            .expect("two-range files should parallelize when shard budget allows");
        assert!(shard_plan.shard_threads >= 2);
        assert!(shard_plan.range_count >= 2);
    }

    #[test]
    fn parallel_fast_count_plan_caps_single_threaded_dominant_literal_only() {
        let file_len = DOMINANT_FILE_PARALLEL_THRESHOLD;
        let literal_plan = parallel_fast_count_plan_with_available(file_len, 1, 32, true)
            .expect("dominant literal files should parallelize with a capped inner budget");
        let non_literal_plan = parallel_fast_count_plan_with_available(file_len, 1, 32, false)
            .expect("dominant non-literal files should preserve the wider legacy budget");

        assert_eq!(
            literal_plan.shard_threads,
            dominant_parallel_thread_cap(threads_90pct(32))
        );
        assert!(non_literal_plan.shard_threads > literal_plan.shard_threads);
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
    fn run_search_max_hits_bounds_retained_hits_without_changing_match_count() {
        let file = unique_temp_path("iex-engine-max-hits-retention").with_extension("txt");
        fs::write(
            &file,
            "alpha needle\nbeta needle\ngamma needle\ndelta needle\n",
        )
        .expect("max-hit fixture should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let mut config = SearchConfig::new(file.clone(), plan);
        config.max_hits = Some(2);
        let report = run_search(&config).expect("max-hit search should succeed");

        assert_eq!(report.stats.matches_found, 4);
        assert_eq!(report.hits.len(), 2);
        assert_eq!(report.hits[0].line, 1);
        assert_eq!(report.hits[0].column, 7);
        assert_eq!(report.hits[1].line, 2);
        assert_eq!(report.hits[1].column, 6);

        let _ = fs::remove_file(file);
    }

    #[test]
    fn run_search_max_hits_keeps_global_first_hits_across_files() {
        let root = unique_temp_path("iex-engine-global-max-hits");
        fs::create_dir_all(&root).expect("root dir should be created");
        let first = root.join("a.txt");
        let second = root.join("b.txt");
        fs::write(&first, "needle one\nneedle two\nneedle three\n")
            .expect("first fixture should write");
        fs::write(&second, "needle four\nneedle five\nneedle six\n")
            .expect("second fixture should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let mut config = SearchConfig::from_roots(vec![second.clone(), first.clone()], plan);
        config.max_hits = Some(2);
        let report = run_search(&config).expect("max-hit multi-file search should succeed");

        assert_eq!(report.stats.matches_found, 6);
        assert_eq!(report.hits.len(), 2);
        assert_eq!(report.hits[0].path, first.display().to_string());
        assert_eq!(report.hits[0].line, 1);
        assert_eq!(report.hits[1].path, first.display().to_string());
        assert_eq!(report.hits[1].line, 2);

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
    fn linux_strategy_surface_stats_only_single_root_serializes_discover_and_path() {
        let root = unique_temp_path("iex-engine-linux-strategy-surface-single");
        fs::create_dir_all(&root).expect("root dir should be created");
        fs::write(root.join("one.txt"), "needle here\n").expect("first fixture should write");
        fs::write(root.join("two.txt"), "needle again\n").expect("second fixture should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let mut config = SearchConfig::new(root.clone(), plan);
        config.collect_hits = false;
        let report = run_search(&config).expect("stats-only search should succeed");
        let json = serde_json::to_value(&report).expect("report should serialize");
        let discover_ms = json["stats"]["timings"]["discover_ms"]
            .as_f64()
            .expect("discover surface should exist");
        let aggregate_merge_ms = json["stats"]["timings"]["aggregate_merge_ms"]
            .as_f64()
            .expect("aggregate merge surface should exist");
        let aggregate_finalize_ms = json["stats"]["timings"]["aggregate_finalize_ms"]
            .as_f64()
            .expect("aggregate finalize surface should exist");
        let aggregate_ms = json["stats"]["timings"]["aggregate_ms"]
            .as_f64()
            .expect("aggregate surface should exist");
        let scan_work_ms_total = json["stats"]["timings"]["scan_work_ms_total"]
            .as_f64()
            .expect("scan work surface should exist");
        let literal_range_calls = json["stats"]["fast_count_density"]["literal_range_calls"]
            .as_u64()
            .expect("literal range calls should exist");
        let literal_range_bytes = json["stats"]["fast_count_density"]["literal_range_bytes"]
            .as_u64()
            .expect("literal range bytes should exist");
        let literal_matches = json["stats"]["fast_count_density"]["literal_matches"]
            .as_u64()
            .expect("literal matches should exist");
        let execution_mode = json["stats"]["concurrency"]["execution_mode"]
            .as_str()
            .expect("execution mode should exist");

        assert!(discover_ms > 0.0);
        assert_eq!(
            execution_mode,
            if prefer_single_root_streaming_stats_only() {
                "streaming_stats_only"
            } else {
                "materialized"
            }
        );
        assert!(aggregate_ms >= aggregate_merge_ms);
        assert!(aggregate_ms >= aggregate_finalize_ms);
        assert!(scan_work_ms_total > 0.0);
        assert!(literal_range_calls <= u64::MAX);
        assert!(literal_range_bytes <= u64::MAX);
        assert!(literal_matches <= u64::MAX);
        assert!(matches!(
            json["stats"]["concurrency"]["sharding_enabled"],
            Value::Bool(_)
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn linux_strategy_surface_stats_only_multi_root_distinguishes_streaming_path() {
        let root = unique_temp_path("iex-engine-linux-strategy-surface-multi");
        let left = root.join("left");
        let right = root.join("right");
        fs::create_dir_all(&left).expect("left dir should be created");
        fs::create_dir_all(&right).expect("right dir should be created");
        fs::write(left.join("one.txt"), "needle here\n").expect("left fixture should write");
        fs::write(right.join("two.txt"), "needle again\n").expect("right fixture should write");

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let mut config = SearchConfig::from_roots(vec![left.clone(), right.clone()], plan);
        config.collect_hits = false;
        let report = run_search(&config).expect("stats-only multi-root search should succeed");
        let json = serde_json::to_value(&report).expect("report should serialize");

        assert!(
            json["stats"]["timings"]["discover_ms"]
                .as_f64()
                .expect("discover surface should exist")
                > 0.0
        );
        assert_eq!(
            json["stats"]["concurrency"]["execution_mode"]
                .as_str()
                .expect("execution mode should exist"),
            "streaming_stats_only"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn linux_strategy_contract_marks_large_single_root_stats_only_lane_eligible() {
        let inputs = LinuxStrategyInputs {
            matcher_strategy_supported: true,
            effective_roots: 1,
            directory_roots: 1,
            root_entry_count: LINUX_STRATEGY_MIN_ROOT_ENTRIES,
            files_discovered: LINUX_STRATEGY_MIN_FILES,
            collect_hits: false,
            outer_parallel_shard_safe: true,
        };

        assert!(linux_strategy_prefers_streaming(inputs));
        assert!(linux_strategy_selector_eligible(inputs));

        let telemetry = linux_strategy_stats(inputs, "materialized");
        assert!(telemetry.selector_eligible);
        assert_eq!(telemetry.current_strategy, "materialized");
        assert!(telemetry.matcher_strategy_supported);
        assert_eq!(telemetry.root_entry_count, LINUX_STRATEGY_MIN_ROOT_ENTRIES);
        assert_eq!(telemetry.files_discovered, LINUX_STRATEGY_MIN_FILES);
        assert!(!telemetry.collect_hits);
        assert!(telemetry.outer_parallel_shard_safe);
    }

    #[test]
    fn linux_strategy_contract_rejects_small_or_collecting_runs() {
        let small_inputs = LinuxStrategyInputs {
            matcher_strategy_supported: true,
            effective_roots: 1,
            directory_roots: 1,
            root_entry_count: LINUX_STRATEGY_MIN_ROOT_ENTRIES - 1,
            files_discovered: LINUX_STRATEGY_MIN_FILES - 1,
            collect_hits: false,
            outer_parallel_shard_safe: false,
        };
        let collecting_inputs = LinuxStrategyInputs {
            matcher_strategy_supported: true,
            effective_roots: 1,
            directory_roots: 1,
            root_entry_count: LINUX_STRATEGY_MIN_ROOT_ENTRIES,
            files_discovered: LINUX_STRATEGY_MIN_FILES,
            collect_hits: true,
            outer_parallel_shard_safe: false,
        };

        assert!(!linux_strategy_prefers_streaming(small_inputs));
        assert!(!linux_strategy_selector_eligible(small_inputs));
        assert!(!linux_strategy_selector_eligible(collecting_inputs));
        assert!(!linux_strategy_stats(small_inputs, "materialized").selector_eligible);
        assert!(!linux_strategy_stats(collecting_inputs, "materialized").selector_eligible);
    }

    #[test]
    fn linux_dominant_file_target_matches_large_amd_asic_reg_headers() {
        let path = Path::new(
            "E:\\Workspaces\\01_Projects\\01_Github\\iEx\\.refs\\ripgrep\\benchsuite\\linux\\drivers\\gpu\\drm\\amd\\include\\asic_reg\\dcn\\dcn_3_2_0_sh_mask.h",
        );

        assert!(is_linux_dominant_file_target(
            path,
            LINUX_DOMINANT_FILE_MIN_BYTES + 1
        ));
    }

    #[test]
    fn linux_dominant_file_target_rejects_small_or_non_amd_headers() {
        let small_path = Path::new(
            "E:\\Workspaces\\01_Projects\\01_Github\\iEx\\.refs\\ripgrep\\benchsuite\\linux\\drivers\\gpu\\drm\\amd\\include\\asic_reg\\nbio\\nbio_7_7_0_sh_mask.h",
        );
        let non_target_path = Path::new(
            "E:\\Workspaces\\01_Projects\\01_Github\\iEx\\.refs\\ripgrep\\benchsuite\\linux\\drivers\\gpu\\drm\\i915\\gvt\\sched_policy.h",
        );

        assert!(!is_linux_dominant_file_target(
            small_path,
            LINUX_DOMINANT_FILE_MIN_BYTES - 1
        ));
        assert!(!is_linux_dominant_file_target(
            non_target_path,
            LINUX_DOMINANT_FILE_MIN_BYTES + 1
        ));
    }

    #[test]
    fn linux_giant_file_gate_opens_for_targeted_stats_only_lanes_without_outer_shard_path() {
        let path = Path::new(
            "E:\\Workspaces\\01_Projects\\01_Github\\iEx\\.refs\\ripgrep\\benchsuite\\linux\\drivers\\gpu\\drm\\amd\\include\\asic_reg\\nbio\\nbio_7_7_0_sh_mask.h",
        );
        let boundary_plan =
            ExpressionPlan::parse(r"re:\bPM_RESUME\b").expect("boundary plan should parse");
        let generic_plan =
            ExpressionPlan::parse(r"re:\w{5}\s+\w{5}").expect("generic plan should parse");

        assert!(linux_dominant_file_gate(
            path,
            &boundary_plan,
            false,
            1,
            LINUX_DOMINANT_FILE_MIN_BYTES + 1
        ));
        assert!(linux_dominant_file_gate(
            path,
            &generic_plan,
            false,
            1,
            LINUX_DOMINANT_FILE_MIN_BYTES + 1
        ));
    }

    #[test]
    fn linux_giant_file_gate_rejects_collecting_and_already_shard_safe_literal_lanes() {
        let path = Path::new(
            "E:\\Workspaces\\01_Projects\\01_Github\\iEx\\.refs\\ripgrep\\benchsuite\\linux\\drivers\\gpu\\drm\\amd\\include\\asic_reg\\nbio\\nbio_7_7_0_sh_mask.h",
        );
        let literal_plan =
            ExpressionPlan::parse("lit:PM_RESUME").expect("literal plan should parse");

        assert!(!linux_dominant_file_gate(
            path,
            &literal_plan,
            false,
            1,
            LINUX_DOMINANT_FILE_MIN_BYTES + 1
        ));
        assert!(!linux_dominant_file_gate(
            path,
            &literal_plan,
            true,
            1,
            LINUX_DOMINANT_FILE_MIN_BYTES + 1
        ));
        assert!(!linux_dominant_file_gate(
            path,
            &ExpressionPlan::parse(r"re:\bPM_RESUME\b").expect("boundary plan should parse"),
            false,
            8,
            LINUX_DOMINANT_FILE_MIN_BYTES + 1
        ));
    }

    #[test]
    fn linux_giant_file_kernel_activates_sharded_fast_count_for_targeted_boundary_lane() {
        let path = Path::new(
            "E:\\Workspaces\\01_Projects\\01_Github\\iEx\\.refs\\ripgrep\\benchsuite\\linux\\drivers\\gpu\\drm\\amd\\include\\asic_reg\\nbio\\nbio_7_7_0_sh_mask.h",
        );
        let plan = ExpressionPlan::parse(r"re:\bPM_RESUME\b").expect("plan should parse");
        let repeat_count = 1_000_000usize;
        let line = b"prefix PM_RESUME suffix PM_RESUME2 trailer\n";
        let bytes = line.repeat(repeat_count);

        assert!(bytes.len() > PARALLEL_FAST_COUNT_FILE_THRESHOLD);

        let outcome = scan_loaded_bytes(
            path,
            None,
            false,
            &plan,
            false,
            None,
            ConcurrencyPlanner {
                available_threads: 32,
            },
            1,
            false,
            &bytes,
            bytes.len() as u64,
        );

        assert_eq!(outcome.match_count, repeat_count);
        assert!(outcome.linux_dominant_file.eligible);
        assert!(outcome.linux_dominant_file.activated);
        assert!(!outcome.linux_dominant_file.bailed_out);
        assert!(outcome.shard_plan.is_some());
        let shard_plan = outcome.shard_plan.expect("targeted kernel should shard");
        assert_eq!(
            outcome.linux_dominant_file.shard_threads,
            shard_plan.shard_threads
        );
        assert_eq!(
            outcome.linux_dominant_file.range_count,
            shard_plan.range_count
        );
        assert_eq!(
            outcome.linux_dominant_file.chunk_bytes,
            shard_plan.chunk_bytes
        );
    }

    #[test]
    fn linux_giant_file_kernel_stays_off_without_range_support() {
        let path = Path::new(
            "E:\\Workspaces\\01_Projects\\01_Github\\iEx\\.refs\\ripgrep\\benchsuite\\linux\\drivers\\gpu\\drm\\amd\\include\\asic_reg\\nbio\\nbio_7_7_0_sh_mask.h",
        );
        let plan = ExpressionPlan::parse(r"re:\w{5}\s+\w{5}").expect("plan should parse");
        let repeat_count = 1_000_000usize;
        let line = b"alpha bravo trailer\n";
        let bytes = line.repeat(repeat_count);
        let expected = plan
            .fast_match_count_no_hits_bytes(&bytes)
            .expect("generic bytes regex should keep canonical count semantics");

        assert!(bytes.len() > PARALLEL_FAST_COUNT_FILE_THRESHOLD);

        let outcome = scan_loaded_bytes(
            path,
            None,
            false,
            &plan,
            false,
            None,
            ConcurrencyPlanner {
                available_threads: 32,
            },
            1,
            false,
            &bytes,
            bytes.len() as u64,
        );

        assert_eq!(outcome.match_count, expected);
        assert!(outcome.linux_dominant_file.eligible);
        assert!(!outcome.linux_dominant_file.activated);
        assert!(outcome.linux_dominant_file.bailed_out);
        assert!(outcome.shard_plan.is_none());
    }

    #[test]
    fn linux_giant_file_budget_keeps_serial_outer_scan_eligible() {
        let file_len = PARALLEL_FAST_COUNT_FILE_THRESHOLD + 4 * 1024;
        let shard_plan = linux_dominant_file_parallel_plan_with_available(file_len, 1, 32)
            .expect("serial outer scans should preserve the targeted inner plan");

        assert_eq!(shard_plan.shard_threads, 3);
        assert_eq!(shard_plan.range_count, 3);
        assert!(shard_plan.chunk_bytes >= PARALLEL_FAST_COUNT_MEDIUM_MIN_CHUNK_BYTES);
    }

    #[test]
    fn linux_giant_file_budget_bails_when_outer_scan_is_parallel() {
        let file_len = PARALLEL_FAST_COUNT_FILE_THRESHOLD + 4 * 1024;

        assert_eq!(
            linux_dominant_file_parallel_plan_with_available(file_len, 2, 32),
            None
        );
        assert_eq!(
            linux_dominant_file_parallel_plan_with_available(file_len, 29, 32),
            None
        );
        assert_eq!(
            linux_dominant_file_parallel_plan_with_available(file_len, 32, 32),
            None
        );
    }

    #[test]
    fn regex_decomposition_stats_only_matches_collecting_totals() {
        let file = unique_temp_path("iex-engine-regex-decomposition").with_extension("txt");
        fs::write(&file, "aa Holmes bb\nxx Holmes yy Holmes zz\nHolmes\n")
            .expect("regex fixture should write");

        let plan = ExpressionPlan::parse(r"re:\w+\s+Holmes\s+\w+").expect("plan should parse");
        let collecting =
            run_search(&SearchConfig::new(file.clone(), plan.clone())).expect("collecting search");

        let mut stats_only_config = SearchConfig::new(file.clone(), plan);
        stats_only_config.collect_hits = false;
        let stats_only = run_search(&stats_only_config).expect("stats-only search");

        assert!(stats_only.hits.is_empty());
        assert_eq!(
            stats_only.stats.matches_found,
            collecting.stats.matches_found
        );
        assert_eq!(stats_only.stats.matches_found, 2);
        assert_eq!(stats_only.stats.acceleration_bailouts, 0);
        assert_eq!(stats_only.stats.regex_decomposition.eligible_files, 1);
        assert_eq!(stats_only.stats.regex_decomposition.counted_files, 1);
        assert_eq!(stats_only.stats.regex_decomposition.bailout_files, 0);
        assert_eq!(
            stats_only.stats.regex_decomposition.candidate_lines_checked,
            2
        );
        assert_eq!(
            stats_only
                .stats
                .regex_decomposition
                .duplicate_candidate_hits_skipped,
            1
        );
        assert_eq!(
            stats_only.stats.regex_decomposition.candidate_lines_matched,
            2
        );

        let _ = fs::remove_file(file);
    }

    #[test]
    fn stats_only_search_reports_unicode_casefold_prefilter_telemetry() {
        let file = unique_temp_path("iex-engine-unicode-casefold-prefilter").with_extension("txt");
        fs::write(
            &file,
            "\u{0428}\u{0435}\u{0440}\u{043b}\u{043e}\u{043a} \u{0425}\u{043e}\u{043b}\u{043c}\u{0441}\n\
\u{0428}\u{0415}\u{0420}\u{041b}\u{041e}\u{041a} \u{0425}\u{041e}\u{041b}\u{041c}\u{0421}\n\
\u{0428}\u{0435}\u{0440}\u{043b}\u{043e} zzz\n",
        )
        .expect("unicode regex fixture should write");

        let plan = ExpressionPlan::parse(
            "re:(?i)\u{0428}\u{0435}\u{0440}\u{043b}\u{043e}\u{043a} \u{0425}\u{043e}\u{043b}\u{043c}\u{0441}",
        )
        .expect("plan should parse");
        let mut stats_only_config = SearchConfig::new(file.clone(), plan);
        stats_only_config.collect_hits = false;
        let stats_only = run_search(&stats_only_config).expect("stats-only search");

        assert!(stats_only.hits.is_empty());
        assert_eq!(stats_only.stats.matches_found, 2);
        assert_eq!(
            stats_only.stats.unicode_casefold_prefilter.full_scan_calls,
            1
        );
        assert_eq!(
            stats_only.stats.unicode_casefold_prefilter.range_scan_calls,
            0
        );
        assert_eq!(
            stats_only
                .stats
                .unicode_casefold_prefilter
                .candidate_prefix_hits,
            3
        );
        assert_eq!(
            stats_only
                .stats
                .unicode_casefold_prefilter
                .confirmed_matches,
            2
        );
        assert_eq!(
            stats_only
                .stats
                .unicode_casefold_prefilter
                .rejected_candidates,
            1
        );
        assert_eq!(
            stats_only
                .stats
                .unicode_casefold_prefilter
                .max_prefix_variant_count,
            32
        );

        let _ = fs::remove_file(file);
    }

    #[test]
    fn regex_decomposition_bails_out_when_candidate_lines_explode() {
        let file = unique_temp_path("iex-engine-regex-decomposition-bailout").with_extension("txt");
        let contents = "aa Holmes bb\n".repeat(5_000);
        fs::write(&file, contents).expect("bailout fixture should write");

        let plan = ExpressionPlan::parse(r"re:\w+\s+Holmes\s+\w+").expect("plan should parse");
        let mut stats_only_config = SearchConfig::new(file.clone(), plan);
        stats_only_config.collect_hits = false;
        let stats_only = run_search(&stats_only_config).expect("stats-only search");

        assert_eq!(stats_only.stats.matches_found, 5_000);
        assert_eq!(stats_only.stats.acceleration_bailouts, 1);
        assert_eq!(stats_only.stats.regex_decomposition.eligible_files, 1);
        assert_eq!(stats_only.stats.regex_decomposition.counted_files, 0);
        assert_eq!(stats_only.stats.regex_decomposition.bailout_files, 1);
        assert_eq!(
            stats_only.stats.regex_decomposition.candidate_lines_checked,
            4_096
        );
        assert_eq!(
            stats_only.stats.regex_decomposition.candidate_lines_matched,
            4_096
        );

        let _ = fs::remove_file(file);
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

        assert_eq!(roots.root_entry_count, 1);
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

    #[test]
    fn prepared_search_targets_skip_discovery_and_preserve_file_set() {
        let root = unique_temp_path("iex-engine-prepared-targets");
        fs::create_dir_all(&root).expect("root dir should be created");
        let alpha = root.join("alpha.txt");
        let beta_dir = root.join("nested");
        let beta = beta_dir.join("beta.txt");
        fs::create_dir_all(&beta_dir).expect("nested dir should be created");
        fs::write(&alpha, "needle alpha\n").expect("alpha fixture should write");
        fs::write(&beta, "needle beta\n").expect("beta fixture should write");

        let prepared = prepare_search_targets(
            vec![root.clone()],
            PreparedSearchOptions {
                include_hidden: false,
                follow_symlinks: false,
            },
        )
        .expect("prepared targets should build");

        assert_eq!(prepared.file_count(), 2);
        assert!(prepared.max_path_depth() >= 1);
        assert!(prepared.path_index_for(&alpha).is_some());
        assert!(prepared.path_index_for(&beta).is_some());
        assert!(!prepared.lazy_path_index_enabled());

        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let config = SearchConfig::from_roots(vec![root.clone()], plan);
        let report =
            run_search_prepared(&config, &prepared).expect("prepared search should succeed");

        assert_eq!(report.stats.timings.discover_ms, 0.0);
        assert!(report.stats.timings.scan_work_ms_total > 0.0);
        assert!(report.stats.timings.aggregate_ms >= report.stats.timings.aggregate_merge_ms);
        assert!(report.stats.timings.aggregate_ms >= report.stats.timings.aggregate_finalize_ms);
        assert!(report.stats.fast_count_density.literal_range_calls <= usize::MAX);
        assert!(report.stats.fast_count_density.literal_range_bytes <= usize::MAX);
        assert!(report.stats.fast_count_density.literal_matches <= usize::MAX);
        assert_eq!(report.stats.files_discovered, 2);
        assert_eq!(report.stats.files_scanned, 2);
        assert_eq!(report.stats.matches_found, 2);
        assert_eq!(
            report.stats.concurrency.execution_mode,
            "materialized_prepared"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn prepared_search_targets_reject_option_mismatch() {
        let root = unique_temp_path("iex-engine-prepared-target-mismatch");
        fs::create_dir_all(&root).expect("root dir should be created");
        fs::write(root.join("needle.txt"), "needle here\n").expect("fixture file should write");

        let prepared = prepare_search_targets(
            vec![root.clone()],
            PreparedSearchOptions {
                include_hidden: false,
                follow_symlinks: false,
            },
        )
        .expect("prepared targets should build");
        let plan = ExpressionPlan::parse("lit:needle").expect("plan should parse");
        let mut config = SearchConfig::from_roots(vec![root.clone()], plan);
        config.include_hidden = true;

        let error = run_search_prepared(&config, &prepared)
            .expect_err("mismatched prepared targets should fail");
        assert!(
            error
                .to_string()
                .contains("prepared search targets were built"),
            "expected mismatch error, got {error}"
        );

        let _ = fs::remove_dir_all(root);
    }
}
