use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectWindowRequest {
    pub path: PathBuf,
    pub start_line: Option<usize>,
    pub end_line: Option<usize>,
    pub skip: usize,
    pub limit: Option<usize>,
    pub allow_full: bool,
}

impl InspectWindowRequest {
    pub fn first(path: impl Into<PathBuf>, limit: usize) -> Self {
        Self {
            path: path.into(),
            start_line: Some(1),
            end_line: None,
            skip: 0,
            limit: Some(limit),
            allow_full: false,
        }
    }

    pub fn range(path: impl Into<PathBuf>, start_line: usize, end_line: usize) -> Self {
        Self {
            path: path.into(),
            start_line: Some(start_line),
            end_line: Some(end_line),
            skip: 0,
            limit: None,
            allow_full: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InspectWindowReport {
    pub path: String,
    pub requested: InspectWindowBounds,
    pub total_emitted_lines: usize,
    pub lines: Vec<InspectLine>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InspectWindowBounds {
    pub start_line: usize,
    pub end_line: Option<usize>,
    pub skip: usize,
    pub limit: Option<usize>,
    pub allow_full: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InspectLine {
    pub line: usize,
    pub text: String,
}

pub fn inspect_window(request: &InspectWindowRequest) -> Result<InspectWindowReport> {
    let bounds = normalize_bounds(request)?;
    let file = File::open(&request.path)
        .with_context(|| format!("failed to open {}", request.path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        if line_number < bounds.start_line {
            continue;
        }
        if bounds
            .end_line
            .is_some_and(|end_line| line_number > end_line)
        {
            break;
        }
        if bounds.limit.is_some_and(|limit| lines.len() >= limit) {
            break;
        }

        let text = line.with_context(|| {
            format!(
                "failed to read UTF-8 line {} from {}",
                line_number,
                request.path.display()
            )
        })?;
        lines.push(InspectLine {
            line: line_number,
            text,
        });
    }

    Ok(InspectWindowReport {
        path: request.path.display().to_string(),
        total_emitted_lines: lines.len(),
        requested: bounds,
        lines,
    })
}

fn normalize_bounds(request: &InspectWindowRequest) -> Result<InspectWindowBounds> {
    if request.start_line == Some(0) {
        bail!("inspection start line must be greater than zero");
    }
    if request.end_line == Some(0) {
        bail!("inspection end line must be greater than zero");
    }
    if request.skip > 0 && request.start_line.is_some() {
        bail!("inspection accepts either --skip or --start-line, not both");
    }

    let start_line = request.start_line.unwrap_or(request.skip + 1);
    if let Some(end_line) = request.end_line {
        if start_line > end_line {
            bail!("inspection range is inverted: start line {start_line} is after end line {end_line}");
        }
    }
    if request.end_line.is_none() && request.limit.is_none() && !request.allow_full {
        bail!("inspection requires --limit, --total-count, --end-line, --range, or explicit --all");
    }

    Ok(InspectWindowBounds {
        start_line,
        end_line: request.end_line,
        skip: request.skip,
        limit: request.limit,
        allow_full: request.allow_full,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn fixture(contents: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ix-inspect-{stamp}.txt"));
        fs::write(&path, contents).expect("fixture write should succeed");
        path
    }

    #[test]
    fn inspects_first_n_lines() {
        let path = fixture("one\ntwo\nthree\n");
        let report = inspect_window(&InspectWindowRequest::first(&path, 2)).unwrap();

        assert_eq!(report.total_emitted_lines, 2);
        assert_eq!(report.lines[0].line, 1);
        assert_eq!(report.lines[0].text, "one");
        assert_eq!(report.lines[1].line, 2);
        assert_eq!(report.lines[1].text, "two");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn inspects_skip_and_limit_window() {
        let path = fixture("one\ntwo\nthree\nfour\n");
        let report = inspect_window(&InspectWindowRequest {
            path: path.clone(),
            start_line: None,
            end_line: None,
            skip: 2,
            limit: Some(2),
            allow_full: false,
        })
        .unwrap();

        assert_eq!(
            report.lines,
            vec![
                InspectLine {
                    line: 3,
                    text: "three".to_owned()
                },
                InspectLine {
                    line: 4,
                    text: "four".to_owned()
                }
            ]
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn inspects_explicit_inclusive_range() {
        let path = fixture("one\ntwo\nthree\nfour\n");
        let report = inspect_window(&InspectWindowRequest::range(&path, 2, 3)).unwrap();

        assert_eq!(report.lines.len(), 2);
        assert_eq!(report.lines[0].line, 2);
        assert_eq!(report.lines[1].line, 3);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn range_beyond_eof_is_empty() {
        let path = fixture("one\n");
        let report = inspect_window(&InspectWindowRequest::range(&path, 8, 9)).unwrap();

        assert!(report.lines.is_empty());
        assert_eq!(report.total_emitted_lines, 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_inverted_range() {
        let path = fixture("one\n");
        let err = inspect_window(&InspectWindowRequest::range(&path, 4, 2)).unwrap_err();

        assert!(format!("{err:#}").contains("inverted"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_implicit_full_file_reads() {
        let path = fixture("one\n");
        let err = inspect_window(&InspectWindowRequest {
            path: path.clone(),
            start_line: Some(1),
            end_line: None,
            skip: 0,
            limit: None,
            allow_full: false,
        })
        .unwrap_err();

        assert!(format!("{err:#}").contains("requires"));
        let _ = fs::remove_file(path);
    }
}
