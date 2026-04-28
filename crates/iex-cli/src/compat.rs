use std::{ffi::OsString, path::PathBuf};

use anyhow::{bail, Result};
use clap::{error::ErrorKind, CommandFactory, Parser};
use regex::escape as regex_escape;

use crate::{search::SearchArgs, Cli, Command};

pub enum Invocation {
    Canonical(Command),
    Compat(SearchArgs),
}

#[derive(Parser, Debug)]
#[command(
    name = "ix",
    no_binary_name = true,
    disable_help_flag = true,
    disable_help_subcommand = true,
    disable_version_flag = true
)]
struct CompatSearchArgs {
    #[arg(short = 'e', long = "regexp", value_name = "PATTERN")]
    regexps: Vec<String>,

    #[arg(short = 'F', long = "fixed-strings")]
    fixed_strings: bool,

    #[arg(short = 'i', long = "ignore-case")]
    ignore_case: bool,

    #[arg(short = 'j', long = "threads")]
    threads: Option<usize>,

    #[arg(short = 'n', long = "line-number")]
    line_number: bool,

    #[arg(long)]
    json: bool,

    #[arg(long)]
    hidden: bool,

    #[arg(value_name = "PATTERN_OR_PATH", num_args = 0..)]
    positionals: Vec<OsString>,
}

pub fn route_invocation(raw_args: Vec<OsString>) -> Result<Invocation> {
    match Cli::try_parse_from(raw_args.clone()) {
        Ok(cli) => Ok(Invocation::Canonical(cli.command)),
        Err(err) => {
            if should_preserve_canonical_parse(&raw_args) {
                err.exit();
            }
            let compat = try_parse_compat_args(&raw_args[1..])?;
            Ok(Invocation::Compat(compat.into_search_args()?))
        }
    }
}

fn should_preserve_canonical_parse(raw_args: &[OsString]) -> bool {
    let Some(first) = raw_args.get(1) else {
        return true;
    };

    matches!(
        first.to_string_lossy().as_ref(),
        "-h" | "--help" | "-V" | "--version" | "help"
    ) || Cli::command()
        .get_subcommands()
        .any(|subcommand| subcommand.get_name() == first.to_string_lossy())
}

fn try_parse_compat_args(raw_args: &[OsString]) -> Result<CompatSearchArgs> {
    CompatSearchArgs::try_parse_from(raw_args.iter().cloned()).map_err(|err| {
        let message = format_compat_parse_error(raw_args, err.kind());
        anyhow::anyhow!(message)
    })
}

fn format_compat_parse_error(raw_args: &[OsString], kind: ErrorKind) -> String {
    if let Some(flag) = first_unsupported_compat_flag(raw_args) {
        let supported = "`ix PATTERN [PATH]...`, `-e/--regexp`, `-F/--fixed-strings`, `-i/--ignore-case`, `-j/--threads`, `-n/--line-number`, `--json`, and `--hidden`";
        return format!(
            "rg-style compatibility does not support `{flag}`. Supported subset: {supported}. Use `ix search <expr> [PATH]...` for native IX syntax."
        );
    }

    if matches!(
        kind,
        ErrorKind::MissingRequiredArgument | ErrorKind::TooFewValues
    ) || compat_patterns_missing(raw_args)
    {
        return "rg-style compatibility expects `ix PATTERN [PATH]...` or `ix -e <PATTERN> [PATH]...`.".to_owned();
    }

    let supported = "`ix PATTERN [PATH]...`, `-e/--regexp`, `-F/--fixed-strings`, `-i/--ignore-case`, `-j/--threads`, `-n/--line-number`, `--json`, and `--hidden`";
    format!(
        "rg-style compatibility could not classify this search request. Supported subset: {supported}. Use `ix search <expr> [PATH]...` for native IX syntax."
    )
}

fn compat_patterns_missing(raw_args: &[OsString]) -> bool {
    let mut expects_value = false;
    for arg in raw_args {
        let text = arg.to_string_lossy();
        if expects_value {
            expects_value = false;
            continue;
        }
        if text == "-e" || text == "--regexp" || text == "-j" || text == "--threads" {
            expects_value = true;
            continue;
        }
        if !text.starts_with('-') {
            return false;
        }
    }
    true
}

fn first_unsupported_compat_flag(raw_args: &[OsString]) -> Option<String> {
    let mut expects_value = false;
    for arg in raw_args {
        let text = arg.to_string_lossy();
        if expects_value {
            expects_value = false;
            continue;
        }

        let flag = text.as_ref();
        if flag == "--" {
            return None;
        }
        if flag == "-e" || flag == "--regexp" || flag == "-j" || flag == "--threads" {
            expects_value = true;
            continue;
        }
        if matches!(
            flag,
            "-F" | "--fixed-strings"
                | "-i"
                | "--ignore-case"
                | "-n"
                | "--line-number"
                | "--json"
                | "--hidden"
        ) {
            continue;
        }
        if flag.starts_with("-j") && flag.len() > 2 {
            continue;
        }
        if flag.starts_with("--threads=") {
            continue;
        }
        if flag.starts_with("-e") && flag.len() > 2 {
            continue;
        }
        if flag.starts_with("--regexp=") {
            continue;
        }
        if flag.starts_with('-') {
            return Some(flag.to_owned());
        }
    }
    None
}

impl CompatSearchArgs {
    fn into_search_args(self) -> Result<SearchArgs> {
        let _ = self.line_number;

        let (patterns, path_args): (Vec<String>, Vec<OsString>) = if self.regexps.is_empty() {
            let (pattern, paths) = self.positionals.split_first().ok_or_else(|| {
                anyhow::anyhow!(
                    "rg-style compatibility expects `ix PATTERN [PATH]...` or `ix -e <PATTERN> [PATH]...`."
                )
            })?;
            (vec![os_string_to_string(pattern)?], paths.to_vec())
        } else {
            (self.regexps, self.positionals)
        };

        let expr = lower_compat_expression(&patterns, self.fixed_strings, self.ignore_case)?;
        let paths = if path_args.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            path_args.into_iter().map(PathBuf::from).collect()
        };

        Ok(SearchArgs {
            expr,
            paths,
            hidden: self.hidden,
            follow_symlinks: false,
            json: self.json,
            stats_only: false,
            max_hits: None,
            threads: self.threads,
            emit_report: None,
        })
    }
}

fn os_string_to_string(value: &OsString) -> Result<String> {
    value
        .clone()
        .into_string()
        .map_err(|_| anyhow::anyhow!("rg-style compatibility requires UTF-8 search patterns"))
}

fn lower_compat_expression(
    patterns: &[String],
    fixed_strings: bool,
    ignore_case: bool,
) -> Result<String> {
    if patterns.is_empty() {
        bail!("rg-style compatibility requires at least one search pattern");
    }

    if patterns.len() == 1 && looks_like_iex_expression(&patterns[0]) {
        if fixed_strings || ignore_case {
            bail!(
                "native IX expressions cannot be combined with `-F` or `-i` in rg-style compatibility mode. Use `ix search <expr> [PATH]...` instead."
            );
        }
        return Ok(patterns[0].trim().to_owned());
    }

    if patterns.iter().any(|pattern| pattern.trim().is_empty()) {
        bail!("rg-style compatibility does not accept empty search patterns");
    }

    if !fixed_strings
        && patterns
            .iter()
            .any(|pattern| pattern.contains("&&") || pattern.contains("||"))
    {
        bail!(
            "regex patterns containing `&&` or `||` are ambiguous with native IX boolean operators. Use `ix search <expr> [PATH]...` for this pattern."
        );
    }

    let lowered: Vec<String> = patterns
        .iter()
        .map(|pattern| lower_compat_pattern(pattern, fixed_strings, ignore_case))
        .collect();
    Ok(lowered.join(" || "))
}

fn lower_compat_pattern(pattern: &str, fixed_strings: bool, ignore_case: bool) -> String {
    if fixed_strings {
        if ignore_case || pattern.contains("&&") || pattern.contains("||") {
            let prefix = if ignore_case { "(?i)" } else { "" };
            return format!("re:{prefix}{}", regex_escape(pattern));
        }
        return format!("lit:{pattern}");
    }

    if ignore_case {
        return format!("re:(?i){pattern}");
    }

    format!("re:{pattern}")
}

fn looks_like_iex_expression(pattern: &str) -> bool {
    let trimmed = pattern.trim();
    trimmed.contains("&&")
        || trimmed.contains("||")
        || trimmed.starts_with("lit:")
        || trimmed.starts_with("re:")
        || trimmed.starts_with("prefix:")
        || trimmed.starts_with("suffix:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_bare_pattern_lowers_to_regex() {
        let compat = try_parse_compat_args(&[OsString::from("timeout"), OsString::from("src")])
            .expect("compat parse should succeed");
        let search = compat
            .into_search_args()
            .expect("compat lowering should succeed");

        assert_eq!(search.expr, "re:timeout");
        assert_eq!(search.paths, vec![PathBuf::from("src")]);
    }

    #[test]
    fn compat_preserves_native_expression_when_bare() {
        let compat = try_parse_compat_args(&[OsString::from("lit:timeout"), OsString::from("src")])
            .expect("compat parse should succeed");
        let search = compat
            .into_search_args()
            .expect("native expression should pass through");

        assert_eq!(search.expr, "lit:timeout");
    }

    #[test]
    fn compat_lowering_supports_repeatable_regexp_flags() {
        let compat = try_parse_compat_args(&[
            OsString::from("-e"),
            OsString::from("timeout"),
            OsString::from("-e"),
            OsString::from("error"),
            OsString::from("src"),
        ])
        .expect("compat parse should succeed");
        let search = compat
            .into_search_args()
            .expect("compat lowering should succeed");

        assert_eq!(search.expr, "re:timeout || re:error");
        assert_eq!(search.paths, vec![PathBuf::from("src")]);
    }

    #[test]
    fn compat_lowering_supports_fixed_string_ignore_case() {
        let compat = try_parse_compat_args(&[
            OsString::from("-F"),
            OsString::from("-i"),
            OsString::from("Timeout.*"),
        ])
        .expect("compat parse should succeed");
        let search = compat
            .into_search_args()
            .expect("compat lowering should succeed");

        assert_eq!(search.expr, r"re:(?i)Timeout\.\*");
        assert_eq!(search.paths, vec![PathBuf::from(".")]);
    }

    #[test]
    fn compat_accepts_json_hidden_threads_and_line_number() {
        let compat = try_parse_compat_args(&[
            OsString::from("--json"),
            OsString::from("--hidden"),
            OsString::from("-n"),
            OsString::from("-j"),
            OsString::from("4"),
            OsString::from("timeout"),
        ])
        .expect("compat parse should succeed");
        let search = compat
            .into_search_args()
            .expect("compat lowering should succeed");

        assert!(search.json);
        assert!(search.hidden);
        assert_eq!(search.threads, Some(4));
        assert_eq!(search.expr, "re:timeout");
    }

    #[test]
    fn compat_reports_guided_unsupported_flags() {
        let error = try_parse_compat_args(&[OsString::from("--files")])
            .expect_err("unsupported flags should fail");
        let message = format!("{error:#}");

        assert!(message.contains("`--files`"));
        assert!(message.contains("Supported subset"));
        assert!(message.contains("ix search <expr> [PATH]..."));
    }

    #[test]
    fn compat_detects_known_subcommands_without_hardcoding() {
        assert!(should_preserve_canonical_parse(&[
            OsString::from("ix"),
            OsString::from("search"),
        ]));
        assert!(should_preserve_canonical_parse(&[
            OsString::from("ix"),
            OsString::from("inspect"),
        ]));
        assert!(!should_preserve_canonical_parse(&[
            OsString::from("ix"),
            OsString::from("timeout"),
        ]));
    }
}
