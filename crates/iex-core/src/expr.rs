use anyhow::{anyhow, Result};
use memchr::memmem;
use regex::{
    bytes::{Regex as BytesRegex, RegexBuilder as BytesRegexBuilder},
    Regex,
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogicMode {
    All,
    Any,
}

#[derive(Debug, Clone)]
enum Predicate {
    Literal { text: String, bytes: Vec<u8> },
    Prefix { text: String, bytes: Vec<u8> },
    Suffix { text: String, bytes: Vec<u8> },
    Regex { text: Regex, bytes: BytesRegex },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PredicateDescriptor {
    Literal(String),
    Prefix(String),
    Suffix(String),
    Regex(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpressionPlan {
    pub source: String,
    pub mode: LogicMode,
    pub predicates: Vec<PredicateDescriptor>,
    #[serde(skip)]
    compiled: Vec<Predicate>,
}

impl ExpressionPlan {
    pub fn parse(raw: &str) -> Result<Self> {
        let source = raw.trim();
        if source.is_empty() {
            return Err(anyhow!("expression cannot be empty"));
        }

        let (mode, tokens): (LogicMode, Vec<&str>) = if source.contains("||") {
            (
                LogicMode::Any,
                source
                    .split("||")
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .collect(),
            )
        } else if source.contains("&&") {
            (
                LogicMode::All,
                source
                    .split("&&")
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .collect(),
            )
        } else {
            (LogicMode::All, vec![source])
        };

        if tokens.is_empty() {
            return Err(anyhow!("expression did not contain any valid tokens"));
        }

        let mut compiled = Vec::with_capacity(tokens.len());
        let mut descriptors = Vec::with_capacity(tokens.len());
        for token in tokens {
            let (predicate, descriptor) = parse_token(token)?;
            compiled.push(predicate);
            descriptors.push(descriptor);
        }

        Ok(Self {
            source: source.to_owned(),
            mode,
            predicates: descriptors,
            compiled,
        })
    }

    pub fn matches(&self, haystack: &str) -> bool {
        match self.mode {
            LogicMode::All => self.compiled.iter().all(|p| predicate_matches(p, haystack)),
            LogicMode::Any => self.compiled.iter().any(|p| predicate_matches(p, haystack)),
        }
    }

    pub fn supports_byte_mode(&self) -> bool {
        true
    }

    pub fn matches_bytes(&self, haystack: &[u8]) -> bool {
        match self.mode {
            LogicMode::All => self
                .compiled
                .iter()
                .all(|p| predicate_matches_bytes(p, haystack)),
            LogicMode::Any => self
                .compiled
                .iter()
                .any(|p| predicate_matches_bytes(p, haystack)),
        }
    }

    pub fn first_match_column(&self, haystack: &str) -> Option<usize> {
        let mut columns: Vec<usize> = self
            .compiled
            .iter()
            .filter_map(|p| predicate_column(p, haystack))
            .collect();

        if columns.is_empty() {
            None
        } else {
            columns.sort_unstable();
            columns.into_iter().next().map(|col| col + 1)
        }
    }

    pub fn first_match_column_bytes(&self, haystack: &[u8]) -> Option<usize> {
        let mut columns: Vec<usize> = self
            .compiled
            .iter()
            .filter_map(|p| predicate_column_bytes(p, haystack))
            .collect();

        if columns.is_empty() {
            None
        } else {
            columns.sort_unstable();
            columns.into_iter().next().map(|col| col + 1)
        }
    }

    pub fn fast_match_count_no_hits(&self, haystack: &str) -> Option<usize> {
        let haystack_bytes = haystack.as_bytes();
        let regex = match self.compiled.as_slice() {
            [Predicate::Regex { bytes, .. }] => bytes,
            _ => return None,
        };
        Some(regex.find_iter(haystack_bytes).count())
    }

    pub fn fast_match_count_no_hits_bytes(&self, haystack: &[u8]) -> Option<usize> {
        let regex = match self.compiled.as_slice() {
            [Predicate::Regex { bytes, .. }] => bytes,
            _ => return None,
        };
        Some(regex.find_iter(haystack).count())
    }
}

fn parse_token(token: &str) -> Result<(Predicate, PredicateDescriptor)> {
    if let Some(value) = token.strip_prefix("re:") {
        let text =
            Regex::new(value).map_err(|err| anyhow!("invalid regex token '{value}': {err}"))?;
        let mut bytes_builder = BytesRegexBuilder::new(value);
        bytes_builder.unicode(false);
        let bytes = bytes_builder
            .build()
            .map_err(|err| anyhow!("invalid regex token '{value}': {err}"))?;
        return Ok((
            Predicate::Regex { text, bytes },
            PredicateDescriptor::Regex(value.to_owned()),
        ));
    }

    if let Some(value) = token.strip_prefix("prefix:") {
        if value.is_empty() {
            return Err(anyhow!("prefix token cannot be empty"));
        }
        return Ok((
            Predicate::Prefix {
                text: value.to_owned(),
                bytes: value.as_bytes().to_vec(),
            },
            PredicateDescriptor::Prefix(value.to_owned()),
        ));
    }

    if let Some(value) = token.strip_prefix("suffix:") {
        if value.is_empty() {
            return Err(anyhow!("suffix token cannot be empty"));
        }
        return Ok((
            Predicate::Suffix {
                text: value.to_owned(),
                bytes: value.as_bytes().to_vec(),
            },
            PredicateDescriptor::Suffix(value.to_owned()),
        ));
    }

    let value = token.strip_prefix("lit:").unwrap_or(token);
    if value.is_empty() {
        return Err(anyhow!("literal token cannot be empty"));
    }

    Ok((
        Predicate::Literal {
            text: value.to_owned(),
            bytes: value.as_bytes().to_vec(),
        },
        PredicateDescriptor::Literal(value.to_owned()),
    ))
}

fn predicate_matches(predicate: &Predicate, haystack: &str) -> bool {
    match predicate {
        Predicate::Literal { text, .. } => haystack.contains(text),
        Predicate::Prefix { text, .. } => haystack.starts_with(text),
        Predicate::Suffix { text, .. } => haystack.ends_with(text),
        Predicate::Regex { text, .. } => text.is_match(haystack),
    }
}

fn predicate_column(predicate: &Predicate, haystack: &str) -> Option<usize> {
    match predicate {
        Predicate::Literal { text, .. } => haystack.find(text),
        Predicate::Prefix { text, .. } => haystack.starts_with(text).then_some(0),
        Predicate::Suffix { text, .. } => haystack
            .ends_with(text)
            .then(|| haystack.len().saturating_sub(text.len())),
        Predicate::Regex { text, .. } => text.find(haystack).map(|m| m.start()),
    }
}

fn predicate_matches_bytes(predicate: &Predicate, haystack: &[u8]) -> bool {
    match predicate {
        Predicate::Literal { bytes, .. } => memmem::find(haystack, bytes).is_some(),
        Predicate::Prefix { bytes, .. } => haystack.starts_with(bytes),
        Predicate::Suffix { bytes, .. } => haystack.ends_with(bytes),
        Predicate::Regex { bytes, .. } => bytes.is_match(haystack),
    }
}

fn predicate_column_bytes(predicate: &Predicate, haystack: &[u8]) -> Option<usize> {
    match predicate {
        Predicate::Literal { bytes, .. } => memmem::find(haystack, bytes),
        Predicate::Prefix { bytes, .. } => haystack.starts_with(bytes).then_some(0),
        Predicate::Suffix { bytes, .. } => haystack
            .ends_with(bytes)
            .then(|| haystack.len().saturating_sub(bytes.len())),
        Predicate::Regex { bytes, .. } => bytes.find(haystack).map(|m| m.start()),
    }
}
