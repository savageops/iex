use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct PhaseTimings {
    pub discover_ms: f64,
    pub scan_ms: f64,
    pub aggregate_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlowFileStat {
    pub path: String,
    pub duration_ms: f64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConcurrencyStats {
    pub available_threads: usize,
    pub outer_scan_threads: usize,
    pub execution_mode: String,
    pub sharding_enabled: bool,
    pub sharded_files: usize,
    pub max_shard_threads: usize,
    pub max_shard_ranges: usize,
    pub max_shard_chunk_bytes: usize,
}

impl Default for ConcurrencyStats {
    fn default() -> Self {
        Self {
            available_threads: 0,
            outer_scan_threads: 0,
            execution_mode: String::new(),
            sharding_enabled: false,
            sharded_files: 0,
            max_shard_threads: 0,
            max_shard_ranges: 0,
            max_shard_chunk_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct RegexDecompositionStats {
    pub eligible_files: usize,
    pub counted_files: usize,
    pub bailout_files: usize,
    pub candidate_lines_checked: usize,
    pub duplicate_candidate_hits_skipped: usize,
    pub candidate_lines_matched: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchStats {
    pub input_roots: usize,
    pub effective_roots: usize,
    pub pruned_roots: usize,
    pub overlap_pruned_roots: usize,
    pub discovered_duplicate_paths: usize,
    pub acceleration_bailouts: usize,
    pub files_discovered: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub matches_found: usize,
    pub bytes_scanned: u64,
    pub regex_decomposition: RegexDecompositionStats,
    pub timings: PhaseTimings,
    pub concurrency: ConcurrencyStats,
    pub slowest_files: Vec<SlowFileStat>,
}

impl Default for SearchStats {
    fn default() -> Self {
        Self {
            input_roots: 0,
            effective_roots: 0,
            pruned_roots: 0,
            overlap_pruned_roots: 0,
            discovered_duplicate_paths: 0,
            acceleration_bailouts: 0,
            files_discovered: 0,
            files_scanned: 0,
            files_skipped: 0,
            matches_found: 0,
            bytes_scanned: 0,
            regex_decomposition: RegexDecompositionStats::default(),
            timings: PhaseTimings::default(),
            concurrency: ConcurrencyStats::default(),
            slowest_files: Vec::new(),
        }
    }
}

impl SearchStats {
    pub fn set_concurrency_context(
        &mut self,
        available_threads: usize,
        outer_scan_threads: usize,
        execution_mode: &str,
    ) {
        self.concurrency.available_threads = available_threads;
        self.concurrency.outer_scan_threads = outer_scan_threads;
        self.concurrency.execution_mode.clear();
        self.concurrency.execution_mode.push_str(execution_mode);
    }

    pub fn observe_parallel_sharding(
        &mut self,
        shard_threads: usize,
        range_count: usize,
        chunk_bytes: usize,
    ) {
        self.concurrency.sharding_enabled = true;
        self.concurrency.sharded_files += 1;
        self.concurrency.max_shard_threads = self.concurrency.max_shard_threads.max(shard_threads);
        self.concurrency.max_shard_ranges = self.concurrency.max_shard_ranges.max(range_count);
        self.concurrency.max_shard_chunk_bytes =
            self.concurrency.max_shard_chunk_bytes.max(chunk_bytes);
    }

    pub fn observe_regex_decomposition(&mut self, telemetry: RegexDecompositionStats) {
        self.regex_decomposition.eligible_files += telemetry.eligible_files;
        self.regex_decomposition.counted_files += telemetry.counted_files;
        self.regex_decomposition.bailout_files += telemetry.bailout_files;
        self.regex_decomposition.candidate_lines_checked += telemetry.candidate_lines_checked;
        self.regex_decomposition.duplicate_candidate_hits_skipped +=
            telemetry.duplicate_candidate_hits_skipped;
        self.regex_decomposition.candidate_lines_matched += telemetry.candidate_lines_matched;
    }

    pub fn consider_slow_file(&mut self, path: &Path, duration_ms: f64, bytes: u64) {
        if self.slowest_files.len() == 5 {
            if let Some(current_slowest) = self.slowest_files.last() {
                if duration_ms <= current_slowest.duration_ms {
                    return;
                }
            }
        }

        self.slowest_files.push(SlowFileStat {
            path: path.display().to_string(),
            duration_ms,
            bytes,
        });
        self.slowest_files
            .sort_by(|a, b| b.duration_ms.total_cmp(&a.duration_ms));
        self.slowest_files.truncate(5);
    }
}
