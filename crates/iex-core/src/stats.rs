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
pub struct SearchStats {
    pub files_discovered: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub matches_found: usize,
    pub bytes_scanned: u64,
    pub timings: PhaseTimings,
    pub slowest_files: Vec<SlowFileStat>,
}

impl Default for SearchStats {
    fn default() -> Self {
        Self {
            files_discovered: 0,
            files_scanned: 0,
            files_skipped: 0,
            matches_found: 0,
            bytes_scanned: 0,
            timings: PhaseTimings::default(),
            slowest_files: Vec::new(),
        }
    }
}

impl SearchStats {
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
