use std::path::Path;

use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default)]
pub struct PhaseTimings {
    pub discover_ms: f64,
    pub scan_ms: f64,
    pub aggregate_ms: f64,
    pub total_ms: f64,
    pub scan_work_ms_total: f64,
    pub aggregate_merge_ms: f64,
    pub aggregate_finalize_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlowFileStat {
    pub path: String,
    pub duration_ms: f64,
    pub bytes: u64,
    pub linux_dominant_target: bool,
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

#[derive(Debug, Clone, Serialize)]
pub struct LinuxDominantFileStats {
    pub target_class: String,
    pub min_bytes: u64,
    pub targeted_files_scanned: usize,
    pub targeted_bytes_scanned: u64,
    pub targeted_slowest_files: usize,
    pub targeted_slowest_bytes: u64,
    pub eligible_files: usize,
    pub activated_files: usize,
    pub bailout_files: usize,
    pub max_shard_threads: usize,
    pub max_range_count: usize,
    pub max_chunk_bytes: usize,
}

impl Default for LinuxDominantFileStats {
    fn default() -> Self {
        Self {
            target_class: String::new(),
            min_bytes: 0,
            targeted_files_scanned: 0,
            targeted_bytes_scanned: 0,
            targeted_slowest_files: 0,
            targeted_slowest_bytes: 0,
            eligible_files: 0,
            activated_files: 0,
            bailout_files: 0,
            max_shard_threads: 0,
            max_range_count: 0,
            max_chunk_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinuxStrategyStats {
    pub selector_eligible: bool,
    pub current_strategy: String,
    pub matcher_strategy_supported: bool,
    pub effective_roots: usize,
    pub directory_roots: usize,
    pub root_entry_count: usize,
    pub files_discovered: usize,
    pub collect_hits: bool,
    pub outer_parallel_shard_safe: bool,
}

impl Default for LinuxStrategyStats {
    fn default() -> Self {
        Self {
            selector_eligible: false,
            current_strategy: String::new(),
            matcher_strategy_supported: false,
            effective_roots: 0,
            directory_roots: 0,
            root_entry_count: 0,
            files_discovered: 0,
            collect_hits: false,
            outer_parallel_shard_safe: false,
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

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
pub struct UnicodeCaseFoldPrefilterStats {
    pub full_scan_calls: usize,
    pub range_scan_calls: usize,
    pub candidate_prefix_hits: usize,
    pub candidate_windows_verified: usize,
    pub confirmed_matches: usize,
    pub rejected_candidates: usize,
    pub candidate_gap_bytes_total: usize,
    pub candidate_gap_samples: usize,
    pub max_prefix_variant_count: usize,
    pub max_prefix_len: usize,
    pub max_match_len: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
pub struct FastCountDensityStats {
    pub literal_reject_fast_calls: usize,
    pub literal_reject_fast_bytes: usize,
    pub literal_range_calls: usize,
    pub literal_range_bytes: usize,
    pub literal_matches: usize,
    pub alternate_reject_fast_calls: usize,
    pub alternate_reject_fast_bytes: usize,
    pub alternate_full_scan_calls: usize,
    pub alternate_full_scan_bytes: usize,
    pub alternate_full_scan_matches: usize,
    pub alternate_range_calls: usize,
    pub alternate_range_bytes: usize,
    pub alternate_matches: usize,
    pub shard_merge_calls: usize,
    pub shard_merge_ranges: usize,
    pub shard_merge_matches: usize,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
pub struct ByteShardKernelStats {
    pub enabled: bool,
    pub files_profiled: usize,
    pub range_calls: usize,
    pub logical_range_bytes: usize,
    pub widened_range_bytes: usize,
    pub overlap_bytes: usize,
    pub range_elapsed_ns_total: u64,
    pub max_range_elapsed_ns: u64,
    pub reduce_elapsed_ns_total: u64,
    pub max_reduce_elapsed_ns: u64,
    pub matches: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct FallbackLineScanStats {
    pub enabled: bool,
    pub files_profiled: usize,
    pub line_count: usize,
    pub candidate_lines: usize,
    pub matched_lines: usize,
    pub scanned_line_bytes: usize,
    pub max_line_bytes: usize,
    pub newline_elapsed_ns_total: u64,
    pub regex_elapsed_ns_total: u64,
    pub max_file_elapsed_ns: u64,
    pub max_file_bytes: u64,
    pub max_file_lines: usize,
    pub max_file_matches: usize,
    pub max_file_path: String,
}

impl FallbackLineScanStats {
    pub fn is_inactive(&self) -> bool {
        !self.enabled
    }
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
    pub linux_strategy: LinuxStrategyStats,
    pub linux_dominant_file: LinuxDominantFileStats,
    pub regex_decomposition: RegexDecompositionStats,
    pub unicode_casefold_prefilter: UnicodeCaseFoldPrefilterStats,
    pub fast_count_density: FastCountDensityStats,
    pub byte_shard_kernel: ByteShardKernelStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_line_scan: Option<FallbackLineScanStats>,
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
            linux_strategy: LinuxStrategyStats::default(),
            linux_dominant_file: LinuxDominantFileStats::default(),
            regex_decomposition: RegexDecompositionStats::default(),
            unicode_casefold_prefilter: UnicodeCaseFoldPrefilterStats::default(),
            fast_count_density: FastCountDensityStats::default(),
            byte_shard_kernel: ByteShardKernelStats::default(),
            fallback_line_scan: None,
            timings: PhaseTimings::default(),
            concurrency: ConcurrencyStats::default(),
            slowest_files: Vec::new(),
        }
    }
}

impl SearchStats {
    pub fn observe_scan_work(&mut self, duration_ms: f64) {
        self.timings.scan_work_ms_total += duration_ms;
    }

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

    pub fn set_linux_dominant_file_context(&mut self, target_class: &str, min_bytes: u64) {
        self.linux_dominant_file.target_class.clear();
        self.linux_dominant_file.target_class.push_str(target_class);
        self.linux_dominant_file.min_bytes = min_bytes;
    }

    pub fn observe_linux_dominant_file_sample(&mut self, targeted: bool, bytes: u64) {
        if targeted {
            self.linux_dominant_file.targeted_files_scanned += 1;
            self.linux_dominant_file.targeted_bytes_scanned += bytes;
        }
    }

    pub fn observe_linux_dominant_file_execution(
        &mut self,
        eligible: bool,
        activated: bool,
        bailed_out: bool,
        shard_threads: usize,
        range_count: usize,
        chunk_bytes: usize,
    ) {
        self.linux_dominant_file.eligible_files += usize::from(eligible);
        self.linux_dominant_file.activated_files += usize::from(activated);
        self.linux_dominant_file.bailout_files += usize::from(bailed_out);
        self.linux_dominant_file.max_shard_threads = self
            .linux_dominant_file
            .max_shard_threads
            .max(shard_threads);
        self.linux_dominant_file.max_range_count =
            self.linux_dominant_file.max_range_count.max(range_count);
        self.linux_dominant_file.max_chunk_bytes =
            self.linux_dominant_file.max_chunk_bytes.max(chunk_bytes);
    }

    pub fn observe_linux_strategy(&mut self, telemetry: LinuxStrategyStats) {
        self.linux_strategy = telemetry;
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

    pub fn observe_unicode_casefold_prefilter(&mut self, telemetry: UnicodeCaseFoldPrefilterStats) {
        self.unicode_casefold_prefilter.full_scan_calls += telemetry.full_scan_calls;
        self.unicode_casefold_prefilter.range_scan_calls += telemetry.range_scan_calls;
        self.unicode_casefold_prefilter.candidate_prefix_hits += telemetry.candidate_prefix_hits;
        self.unicode_casefold_prefilter.candidate_windows_verified +=
            telemetry.candidate_windows_verified;
        self.unicode_casefold_prefilter.confirmed_matches += telemetry.confirmed_matches;
        self.unicode_casefold_prefilter.rejected_candidates += telemetry.rejected_candidates;
        self.unicode_casefold_prefilter.candidate_gap_bytes_total +=
            telemetry.candidate_gap_bytes_total;
        self.unicode_casefold_prefilter.candidate_gap_samples += telemetry.candidate_gap_samples;
        self.unicode_casefold_prefilter.max_prefix_variant_count = self
            .unicode_casefold_prefilter
            .max_prefix_variant_count
            .max(telemetry.max_prefix_variant_count);
        self.unicode_casefold_prefilter.max_prefix_len = self
            .unicode_casefold_prefilter
            .max_prefix_len
            .max(telemetry.max_prefix_len);
        self.unicode_casefold_prefilter.max_match_len = self
            .unicode_casefold_prefilter
            .max_match_len
            .max(telemetry.max_match_len);
    }

    pub fn observe_fast_count_density(&mut self, telemetry: FastCountDensityStats) {
        self.fast_count_density.literal_reject_fast_calls += telemetry.literal_reject_fast_calls;
        self.fast_count_density.literal_reject_fast_bytes += telemetry.literal_reject_fast_bytes;
        self.fast_count_density.literal_range_calls += telemetry.literal_range_calls;
        self.fast_count_density.literal_range_bytes += telemetry.literal_range_bytes;
        self.fast_count_density.literal_matches += telemetry.literal_matches;
        self.fast_count_density.alternate_reject_fast_calls +=
            telemetry.alternate_reject_fast_calls;
        self.fast_count_density.alternate_reject_fast_bytes +=
            telemetry.alternate_reject_fast_bytes;
        self.fast_count_density.alternate_full_scan_calls += telemetry.alternate_full_scan_calls;
        self.fast_count_density.alternate_full_scan_bytes += telemetry.alternate_full_scan_bytes;
        self.fast_count_density.alternate_full_scan_matches +=
            telemetry.alternate_full_scan_matches;
        self.fast_count_density.alternate_range_calls += telemetry.alternate_range_calls;
        self.fast_count_density.alternate_range_bytes += telemetry.alternate_range_bytes;
        self.fast_count_density.alternate_matches += telemetry.alternate_matches;
        self.fast_count_density.shard_merge_calls += telemetry.shard_merge_calls;
        self.fast_count_density.shard_merge_ranges += telemetry.shard_merge_ranges;
        self.fast_count_density.shard_merge_matches += telemetry.shard_merge_matches;
    }

    pub fn observe_byte_shard_kernel(&mut self, telemetry: ByteShardKernelStats) {
        self.byte_shard_kernel.enabled |= telemetry.enabled;
        self.byte_shard_kernel.files_profiled += telemetry.files_profiled;
        self.byte_shard_kernel.range_calls += telemetry.range_calls;
        self.byte_shard_kernel.logical_range_bytes += telemetry.logical_range_bytes;
        self.byte_shard_kernel.widened_range_bytes += telemetry.widened_range_bytes;
        self.byte_shard_kernel.overlap_bytes += telemetry.overlap_bytes;
        self.byte_shard_kernel.range_elapsed_ns_total += telemetry.range_elapsed_ns_total;
        self.byte_shard_kernel.max_range_elapsed_ns = self
            .byte_shard_kernel
            .max_range_elapsed_ns
            .max(telemetry.max_range_elapsed_ns);
        self.byte_shard_kernel.reduce_elapsed_ns_total += telemetry.reduce_elapsed_ns_total;
        self.byte_shard_kernel.max_reduce_elapsed_ns = self
            .byte_shard_kernel
            .max_reduce_elapsed_ns
            .max(telemetry.max_reduce_elapsed_ns);
        self.byte_shard_kernel.matches += telemetry.matches;
    }

    pub fn observe_fallback_line_scan(&mut self, telemetry: Option<FallbackLineScanStats>) {
        let Some(telemetry) = telemetry else {
            return;
        };
        let aggregate = self.fallback_line_scan.get_or_insert_with(Default::default);
        aggregate.enabled |= telemetry.enabled;
        aggregate.files_profiled += telemetry.files_profiled;
        aggregate.line_count += telemetry.line_count;
        aggregate.candidate_lines += telemetry.candidate_lines;
        aggregate.matched_lines += telemetry.matched_lines;
        aggregate.scanned_line_bytes += telemetry.scanned_line_bytes;
        aggregate.max_line_bytes = aggregate.max_line_bytes.max(telemetry.max_line_bytes);
        aggregate.newline_elapsed_ns_total += telemetry.newline_elapsed_ns_total;
        aggregate.regex_elapsed_ns_total += telemetry.regex_elapsed_ns_total;
        if telemetry.max_file_elapsed_ns > aggregate.max_file_elapsed_ns {
            aggregate.max_file_elapsed_ns = telemetry.max_file_elapsed_ns;
            aggregate.max_file_bytes = telemetry.max_file_bytes;
            aggregate.max_file_lines = telemetry.max_file_lines;
            aggregate.max_file_matches = telemetry.max_file_matches;
            aggregate.max_file_path = telemetry.max_file_path;
        }
    }

    pub fn consider_slow_file(
        &mut self,
        path: &Path,
        duration_ms: f64,
        bytes: u64,
        linux_dominant_target: bool,
    ) {
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
            linux_dominant_target,
        });
        self.slowest_files
            .sort_by(|a, b| b.duration_ms.total_cmp(&a.duration_ms));
        self.slowest_files.truncate(5);
        self.refresh_targeted_slowest_summary();
    }

    fn refresh_targeted_slowest_summary(&mut self) {
        self.linux_dominant_file.targeted_slowest_files = self
            .slowest_files
            .iter()
            .filter(|file| file.linux_dominant_target)
            .count();
        self.linux_dominant_file.targeted_slowest_bytes = self
            .slowest_files
            .iter()
            .filter(|file| file.linux_dominant_target)
            .map(|file| file.bytes)
            .sum();
    }
}
