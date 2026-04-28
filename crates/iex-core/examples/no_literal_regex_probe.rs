use regex::bytes::Regex;
use serde_json::json;
use std::{fs, hint::black_box, time::Instant};

fn timed<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let start = Instant::now();
    (f(), start.elapsed().as_secs_f64() * 1000.0)
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    values[values.len() / 2]
}

fn count_find_then_tail(regex: &Regex, haystack: &[u8]) -> usize {
    match regex.find(haystack) {
        None => 0,
        Some(first) if first.is_empty() => regex.find_iter(haystack).count(),
        Some(first) => 1 + regex.find_iter(&haystack[first.end()..]).count(),
    }
}

fn count_shortest_then_full(regex: &Regex, haystack: &[u8]) -> usize {
    match regex.shortest_match(haystack) {
        None => 0,
        Some(_) => regex.find_iter(haystack).count(),
    }
}

fn main() {
    let corpus = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".refs/ripgrep/benchsuite/subtitles/en.sample.txt".to_owned());
    let iterations = std::env::args()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(41);
    let haystack = fs::read(&corpus).expect("read corpus");
    let pattern = r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}";
    let regex = Regex::new(pattern).expect("compile regex");
    let mut timings = [(); 4].map(|_| Vec::with_capacity(iterations));
    let mut counts = (0, 0, 0, false);

    for _ in 0..4 {
        black_box(regex.find_iter(black_box(&haystack)).count());
        black_box(count_find_then_tail(&regex, black_box(&haystack)));
        black_box(count_shortest_then_full(&regex, black_box(&haystack)));
        black_box(regex.is_match(black_box(&haystack)));
    }

    for round in 0..iterations {
        for slot in 0..4 {
            match (round + slot) % 4 {
                0 => {
                    let (count, ms) =
                        timed(|| black_box(regex.find_iter(black_box(&haystack)).count()));
                    counts.0 = count;
                    timings[0].push(ms);
                }
                1 => {
                    let (count, ms) =
                        timed(|| black_box(count_find_then_tail(&regex, black_box(&haystack))));
                    counts.1 = count;
                    timings[1].push(ms);
                }
                2 => {
                    let (count, ms) =
                        timed(|| black_box(count_shortest_then_full(&regex, black_box(&haystack))));
                    counts.2 = count;
                    timings[2].push(ms);
                }
                _ => {
                    let (matched, ms) = timed(|| black_box(regex.is_match(black_box(&haystack))));
                    counts.3 = matched;
                    timings[3].push(ms);
                }
            }
        }
    }

    let find_iter = median(&mut timings[0]);
    let find_then_tail = median(&mut timings[1]);
    let shortest_then_full = median(&mut timings[2]);
    let is_match = median(&mut timings[3]);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "corpus": corpus,
            "bytes": haystack.len(),
            "pattern": pattern,
            "iterations": iterations,
            "counts": {
                "find_iter": counts.0,
                "find_then_tail": counts.1,
                "shortest_then_full": counts.2,
                "is_match": counts.3
            },
            "medians_ms": {
                "find_iter": find_iter,
                "find_then_tail": find_then_tail,
                "shortest_then_full": shortest_then_full,
                "is_match": is_match
            },
            "ratios_to_find_iter": {
                "find_then_tail": find_then_tail / find_iter,
                "shortest_then_full": shortest_then_full / find_iter,
                "is_match": is_match / find_iter
            }
        }))
        .expect("json")
    );
}
