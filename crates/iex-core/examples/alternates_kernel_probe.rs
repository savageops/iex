use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use anyhow::{anyhow, Context, Result};
use memchr::memmem;
use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const DEFAULT_PATTERNS: [&str; 4] = ["ERR_SYS", "PME_TURN_OFF", "LINK_REQ_RST", "CFG_BME_EVT"];

#[derive(Debug)]
struct Args {
    corpus: PathBuf,
    output: Option<PathBuf>,
    samples: usize,
    warmup: usize,
    range_counts: Vec<usize>,
    patterns: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct CorpusFile {
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct AcVariant {
    name: &'static str,
    match_kind: MatchKind,
    automaton_kind: Option<AhoCorasickKind>,
    prefilter: bool,
    ascii_case_insensitive: bool,
}

#[derive(Debug)]
struct TimedCount {
    count: usize,
    elapsed_ns: u128,
}

fn main() -> Result<()> {
    let args = parse_args(env::args().skip(1))?;
    let files = read_corpus(&args.corpus)?;
    if files.is_empty() {
        return Err(anyhow!("corpus has no files: {}", args.corpus.display()));
    }

    let total_bytes = files.iter().map(|file| file.bytes.len()).sum::<usize>();
    let max_literal_len = args
        .patterns
        .iter()
        .map(Vec::len)
        .max()
        .context("at least one pattern is required")?;

    let baseline = build_automaton(MatchKind::LeftmostFirst, None, true, false, &args.patterns)?;
    let baseline_count = count_ac_whole(&files, &baseline);

    let variants = [
        AcVariant {
            name: "leftmost-auto-prefilter-on",
            match_kind: MatchKind::LeftmostFirst,
            automaton_kind: None,
            prefilter: true,
            ascii_case_insensitive: false,
        },
        AcVariant {
            name: "leftmost-auto-prefilter-off",
            match_kind: MatchKind::LeftmostFirst,
            automaton_kind: None,
            prefilter: false,
            ascii_case_insensitive: false,
        },
        AcVariant {
            name: "leftmost-contiguous-nfa-prefilter-on",
            match_kind: MatchKind::LeftmostFirst,
            automaton_kind: Some(AhoCorasickKind::ContiguousNFA),
            prefilter: true,
            ascii_case_insensitive: false,
        },
        AcVariant {
            name: "leftmost-dfa-prefilter-on",
            match_kind: MatchKind::LeftmostFirst,
            automaton_kind: Some(AhoCorasickKind::DFA),
            prefilter: true,
            ascii_case_insensitive: false,
        },
        AcVariant {
            name: "standard-auto-prefilter-on",
            match_kind: MatchKind::Standard,
            automaton_kind: None,
            prefilter: true,
            ascii_case_insensitive: false,
        },
        AcVariant {
            name: "standard-dfa-prefilter-on",
            match_kind: MatchKind::Standard,
            automaton_kind: Some(AhoCorasickKind::DFA),
            prefilter: true,
            ascii_case_insensitive: false,
        },
    ];

    let mut variant_reports = Vec::new();
    for variant in variants {
        let started = Instant::now();
        let automaton = build_automaton(
            variant.match_kind,
            variant.automaton_kind,
            variant.prefilter,
            variant.ascii_case_insensitive,
            &args.patterns,
        )?;
        let build_ns = started.elapsed().as_nanos();

        for _ in 0..args.warmup {
            let _ = count_ac_whole(&files, &automaton);
        }

        let samples = measure_whole(&files, &automaton, args.samples);
        let counts = samples
            .iter()
            .map(|sample| sample.count)
            .collect::<Vec<_>>();
        let elapsed = samples
            .iter()
            .map(|sample| sample.elapsed_ns)
            .collect::<Vec<_>>();
        let median_ns = median_u128(elapsed.clone());
        let comparable = counts.iter().all(|count| *count == baseline_count);

        variant_reports.push(json!({
            "name": variant.name,
            "requested_match_kind": format!("{:?}", variant.match_kind),
            "requested_automaton_kind": format_automaton_kind(variant.automaton_kind),
            "actual_automaton_kind": format!("{:?}", automaton.kind()),
            "actual_match_kind": format!("{:?}", automaton.match_kind()),
            "prefilter": variant.prefilter,
            "ascii_case_insensitive": variant.ascii_case_insensitive,
            "build_ns": build_ns,
            "median_ns": median_ns,
            "median_ms": ns_to_ms(median_ns),
            "throughput_mib_s": throughput_mib_s(total_bytes, median_ns),
            "counts": counts,
            "comparable_to_leftmost_baseline": comparable,
            "samples_ns": elapsed,
        }));
    }

    let mut range_reports = Vec::new();
    for range_count in args.range_counts.iter().copied().filter(|count| *count > 0) {
        for _ in 0..args.warmup {
            let _ = count_ac_ranges(&files, &baseline, max_literal_len, range_count);
        }
        let mut samples = Vec::new();
        for _ in 0..args.samples {
            let started = Instant::now();
            let count = count_ac_ranges(&files, &baseline, max_literal_len, range_count);
            samples.push(TimedCount {
                count,
                elapsed_ns: started.elapsed().as_nanos(),
            });
        }
        let counts = samples
            .iter()
            .map(|sample| sample.count)
            .collect::<Vec<_>>();
        let elapsed = samples
            .iter()
            .map(|sample| sample.elapsed_ns)
            .collect::<Vec<_>>();
        let visited_bytes = visited_range_bytes(&files, max_literal_len, range_count);
        let median_ns = median_u128(elapsed.clone());

        range_reports.push(json!({
            "range_count": range_count,
            "max_literal_len": max_literal_len,
            "owned_bytes": total_bytes,
            "visited_bytes": visited_bytes,
            "overlap_amplification": if total_bytes == 0 { 0.0 } else { visited_bytes as f64 / total_bytes as f64 },
            "median_ns": median_ns,
            "median_ms": ns_to_ms(median_ns),
            "throughput_mib_s": throughput_mib_s(visited_bytes, median_ns),
            "counts": counts,
            "comparable_to_leftmost_baseline": counts.iter().all(|count| *count == baseline_count),
            "samples_ns": elapsed,
        }));
    }

    let finders = args
        .patterns
        .iter()
        .map(|pattern| memmem::Finder::new(pattern))
        .collect::<Vec<_>>();
    for _ in 0..args.warmup {
        let _ = count_memmem_sum(&files, &finders);
    }
    let memmem_samples = measure_memmem_sum(&files, &finders, args.samples);
    let memmem_counts = memmem_samples
        .iter()
        .map(|sample| sample.count)
        .collect::<Vec<_>>();
    let memmem_elapsed = memmem_samples
        .iter()
        .map(|sample| sample.elapsed_ns)
        .collect::<Vec<_>>();
    let memmem_median_ns = median_u128(memmem_elapsed.clone());

    let report = json!({
        "probe": "alternates_kernel_probe",
        "corpus": args.corpus,
        "file_count": files.len(),
        "total_bytes": total_bytes,
        "patterns": args.patterns.iter().map(|pattern| String::from_utf8_lossy(pattern).to_string()).collect::<Vec<_>>(),
        "samples": args.samples,
        "warmup": args.warmup,
        "leftmost_baseline_count": baseline_count,
        "variants": variant_reports,
        "range_geometry": range_reports,
        "memmem_sum_control": {
            "median_ns": memmem_median_ns,
            "median_ms": ns_to_ms(memmem_median_ns),
            "throughput_mib_s": throughput_mib_s(total_bytes, memmem_median_ns),
            "counts": memmem_counts,
            "comparable_to_leftmost_baseline": memmem_counts.iter().all(|count| *count == baseline_count),
            "samples_ns": memmem_elapsed,
            "semantic_note": "sum of independent literal occurrences; only comparable when literals cannot overlap or duplicate AC leftmost semantics"
        }
    });

    let formatted = serde_json::to_string_pretty(&report)?;
    println!("{formatted}");

    if let Some(output) = args.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&output, formatted)
            .with_context(|| format!("failed to write {}", output.display()))?;
    }

    Ok(())
}

fn parse_args(raw_args: impl Iterator<Item = String>) -> Result<Args> {
    let mut corpus = PathBuf::from(".refs/ripgrep/benchsuite/linux");
    let mut output = None;
    let mut samples = 7;
    let mut warmup = 1;
    let mut range_counts = vec![1, 2, 4, 8, 16];
    let mut patterns = Vec::new();
    let mut args = raw_args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--corpus" => {
                corpus = PathBuf::from(next_value(&mut args, "--corpus")?);
            }
            "--output" => {
                output = Some(PathBuf::from(next_value(&mut args, "--output")?));
            }
            "--samples" => {
                samples = next_value(&mut args, "--samples")?
                    .parse()
                    .context("--samples must be an integer")?;
            }
            "--warmup" => {
                warmup = next_value(&mut args, "--warmup")?
                    .parse()
                    .context("--warmup must be an integer")?;
            }
            "--range-counts" => {
                range_counts = next_value(&mut args, "--range-counts")?
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(|part| part.parse().context("range count must be an integer"))
                    .collect::<Result<Vec<_>>>()?;
            }
            "--pattern" => {
                patterns.push(next_value(&mut args, "--pattern")?.into_bytes());
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    if patterns.is_empty() {
        patterns = DEFAULT_PATTERNS
            .iter()
            .map(|pattern| pattern.as_bytes().to_vec())
            .collect();
    }
    if samples == 0 {
        return Err(anyhow!("--samples must be greater than zero"));
    }

    Ok(Args {
        corpus,
        output,
        samples,
        warmup,
        range_counts,
        patterns,
    })
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next()
        .ok_or_else(|| anyhow!("{flag} requires a following value"))
}

fn print_help() {
    println!(
        "usage: cargo run --release -p iex-core --example alternates_kernel_probe -- [--corpus PATH] [--output PATH] [--samples N] [--warmup N] [--range-counts 1,2,4,8] [--pattern LITERAL ...]"
    );
}

fn read_corpus(root: &Path) -> Result<Vec<CorpusFile>> {
    let mut paths = Vec::new();
    collect_files(root, &mut paths)?;
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path)
                .with_context(|| format!("failed to read corpus file {}", path.display()))?;
            Ok(CorpusFile { bytes })
        })
        .collect()
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn build_automaton(
    match_kind: MatchKind,
    automaton_kind: Option<AhoCorasickKind>,
    prefilter: bool,
    ascii_case_insensitive: bool,
    patterns: &[Vec<u8>],
) -> Result<AhoCorasick> {
    AhoCorasickBuilder::new()
        .match_kind(match_kind)
        .kind(automaton_kind)
        .prefilter(prefilter)
        .ascii_case_insensitive(ascii_case_insensitive)
        .build(patterns.iter().map(Vec::as_slice))
        .context("failed to build Aho-Corasick automaton")
}

fn measure_whole(files: &[CorpusFile], automaton: &AhoCorasick, samples: usize) -> Vec<TimedCount> {
    (0..samples)
        .map(|_| {
            let started = Instant::now();
            let count = count_ac_whole(files, automaton);
            TimedCount {
                count,
                elapsed_ns: started.elapsed().as_nanos(),
            }
        })
        .collect()
}

fn count_ac_whole(files: &[CorpusFile], automaton: &AhoCorasick) -> usize {
    files
        .iter()
        .map(|file| automaton.find_iter(&file.bytes).count())
        .sum()
}

fn count_ac_ranges(
    files: &[CorpusFile],
    automaton: &AhoCorasick,
    max_literal_len: usize,
    range_count: usize,
) -> usize {
    files
        .iter()
        .map(|file| count_ac_ranges_for_file(&file.bytes, automaton, max_literal_len, range_count))
        .sum()
}

fn count_ac_ranges_for_file(
    haystack: &[u8],
    automaton: &AhoCorasick,
    max_literal_len: usize,
    range_count: usize,
) -> usize {
    if haystack.is_empty() {
        return 0;
    }
    let overlap = max_literal_len.saturating_sub(1);
    let chunk_len = haystack.len().div_ceil(range_count);
    let mut count = 0;

    for range_index in 0..range_count {
        let start = range_index * chunk_len;
        if start >= haystack.len() {
            break;
        }
        let end = ((range_index + 1) * chunk_len).min(haystack.len());
        let slice_start = start.saturating_sub(overlap);
        let slice_end = end.saturating_add(overlap).min(haystack.len());
        let slice = &haystack[slice_start..slice_end];

        count += automaton
            .find_iter(slice)
            .filter(|mat| {
                let absolute_start = slice_start + mat.start();
                absolute_start >= start && absolute_start < end
            })
            .count();
    }

    count
}

fn visited_range_bytes(files: &[CorpusFile], max_literal_len: usize, range_count: usize) -> usize {
    files
        .iter()
        .map(|file| visited_range_bytes_for_file(file.bytes.len(), max_literal_len, range_count))
        .sum()
}

fn visited_range_bytes_for_file(len: usize, max_literal_len: usize, range_count: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let overlap = max_literal_len.saturating_sub(1);
    let chunk_len = len.div_ceil(range_count);
    let mut visited = 0;

    for range_index in 0..range_count {
        let start = range_index * chunk_len;
        if start >= len {
            break;
        }
        let end = ((range_index + 1) * chunk_len).min(len);
        let slice_start = start.saturating_sub(overlap);
        let slice_end = end.saturating_add(overlap).min(len);
        visited += slice_end - slice_start;
    }

    visited
}

fn measure_memmem_sum(
    files: &[CorpusFile],
    finders: &[memmem::Finder],
    samples: usize,
) -> Vec<TimedCount> {
    (0..samples)
        .map(|_| {
            let started = Instant::now();
            let count = count_memmem_sum(files, finders);
            TimedCount {
                count,
                elapsed_ns: started.elapsed().as_nanos(),
            }
        })
        .collect()
}

fn count_memmem_sum(files: &[CorpusFile], finders: &[memmem::Finder]) -> usize {
    files
        .iter()
        .map(|file| {
            finders
                .iter()
                .map(|finder| finder.find_iter(&file.bytes).count())
                .sum::<usize>()
        })
        .sum()
}

fn median_u128(mut values: Vec<u128>) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn ns_to_ms(ns: u128) -> f64 {
    ns as f64 / 1_000_000.0
}

fn throughput_mib_s(bytes: usize, ns: u128) -> f64 {
    if ns == 0 {
        return 0.0;
    }
    let seconds = ns as f64 / 1_000_000_000.0;
    (bytes as f64 / (1024.0 * 1024.0)) / seconds
}

fn format_automaton_kind(kind: Option<AhoCorasickKind>) -> String {
    match kind {
        Some(kind) => format!("{kind:?}"),
        None => "auto".to_string(),
    }
}
