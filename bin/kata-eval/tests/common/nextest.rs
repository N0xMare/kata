//! The subset of nextest's configuration language the gate uses: filtersets, each
//! profile's `default-filter`, and the slow-timeout kill a profile resolves for a test.

use std::collections::BTreeMap;

use super::rust_tree::TargetKind;

/// A test as nextest's filterset language sees it.
pub struct TestIdentity<'a> {
    pub package: &'a str,
    pub binary_name: &'a str,
    pub binary_id: String,
    pub kind: TargetKind,
    pub test: &'a str,
}

#[derive(Clone, Debug)]
pub enum Matcher {
    Equal(String),
    Contains(String),
}

impl Matcher {
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Matcher::Equal(expected) => value == expected,
            Matcher::Contains(needle) => value.contains(needle.as_str()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Filterset {
    All,
    None,
    Package(Matcher),
    Binary(Matcher),
    BinaryId(Matcher),
    Kind(Matcher),
    Test(Matcher),
    Not(Box<Filterset>),
    And(Box<Filterset>, Box<Filterset>),
    Or(Box<Filterset>, Box<Filterset>),
}

impl Filterset {
    pub fn matches(&self, test: &TestIdentity<'_>) -> bool {
        match self {
            Filterset::All => true,
            Filterset::None => false,
            Filterset::Package(matcher) => matcher.matches(test.package),
            Filterset::Binary(matcher) => matcher.matches(test.binary_name),
            Filterset::BinaryId(matcher) => matcher.matches(&test.binary_id),
            Filterset::Kind(matcher) => matcher.matches(test.kind.as_str()),
            Filterset::Test(matcher) => matcher.matches(test.test),
            Filterset::Not(inner) => !inner.matches(test),
            Filterset::And(left, right) => left.matches(test) && right.matches(test),
            Filterset::Or(left, right) => left.matches(test) || right.matches(test),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FilterToken {
    Open,
    Close,
    Or,
    And,
    Minus,
    Not,
    Predicate(String, String),
}

/// Parse the filterset subset in use: `package`, `binary`, `binary_id`, `kind`,
/// `test`, `all`, `none`, `not`/`!`, `and`/`&`, `or`/`|`/`+`, `-`, and parentheses,
/// with `=` (exact), `~` (contains) and the default matcher. A regex, a glob with
/// metacharacters, or any other predicate is REFUSED rather than guessed: a filter
/// this file misreads would move a cell between layers without a word.
pub fn parse_filterset(expression: &str) -> Result<Filterset, String> {
    let tokens = filter_tokens(expression)?;
    let mut at = 0;
    let parsed = parse_or(&tokens, &mut at)?;
    if at != tokens.len() {
        return Err(format!(
            "unexpected trailing input in filterset `{expression}`"
        ));
    }
    Ok(parsed)
}

/// Each `not` / `!` in `expression` whose operand is not ONE `test(...)` predicate: a
/// parenthesised group (even one around a single `test(...)`), another predicate,
/// another negation. Only the tokens can say: [`parse_filterset`] drops parentheses,
/// so `not (test(x))` and `not test(x)` parse to the same tree, while a text reader
/// that looks for the negation right before `test(` reads only the second.
pub fn negations_not_of_one_test_predicate(expression: &str) -> Result<Vec<String>, String> {
    let tokens = filter_tokens(expression)?;
    Ok(tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| **token == FilterToken::Not)
        .filter_map(|(at, _)| match tokens.get(at + 1) {
            Some(FilterToken::Predicate(name, _)) if name == "test" => None,
            Some(FilterToken::Predicate(name, argument)) => Some(format!(
                "it negates `{name}({argument})`, not a `test(...)` predicate"
            )),
            Some(FilterToken::Open) => {
                Some("it negates a parenthesised group, not one bare `test(...)` predicate".into())
            }
            other => Some(format!(
                "it negates {other:?}, not one `test(...)` predicate"
            )),
        })
        .collect())
}

fn filter_tokens(expression: &str) -> Result<Vec<FilterToken>, String> {
    let chars: Vec<char> = expression.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        match ch {
            _ if ch.is_whitespace() => index += 1,
            '(' => {
                tokens.push(FilterToken::Open);
                index += 1;
            }
            ')' => {
                tokens.push(FilterToken::Close);
                index += 1;
            }
            '|' | '+' => {
                tokens.push(FilterToken::Or);
                index += 1;
            }
            '&' => {
                tokens.push(FilterToken::And);
                index += 1;
            }
            '-' => {
                tokens.push(FilterToken::Minus);
                index += 1;
            }
            '!' => {
                tokens.push(FilterToken::Not);
                index += 1;
            }
            _ if ch.is_ascii_alphabetic() => {
                let start = index;
                while index < chars.len()
                    && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
                {
                    index += 1;
                }
                let word: String = chars[start..index].iter().collect();
                match word.as_str() {
                    "not" => tokens.push(FilterToken::Not),
                    "and" => tokens.push(FilterToken::And),
                    "or" => tokens.push(FilterToken::Or),
                    _ => {
                        if chars.get(index) != Some(&'(') {
                            return Err(format!("`{word}` is not a filterset predicate call"));
                        }
                        let close = chars[index..]
                            .iter()
                            .position(|c| *c == ')')
                            .ok_or_else(|| format!("unclosed `{word}(`"))?
                            + index;
                        let argument: String = chars[index + 1..close].iter().collect();
                        tokens.push(FilterToken::Predicate(word, argument.trim().to_string()));
                        index = close + 1;
                    }
                }
            }
            _ => {
                return Err(format!(
                    "unsupported filterset character `{ch}` in `{expression}`"
                ));
            }
        }
    }
    Ok(tokens)
}

fn parse_or(tokens: &[FilterToken], at: &mut usize) -> Result<Filterset, String> {
    let mut left = parse_and(tokens, at)?;
    while tokens.get(*at) == Some(&FilterToken::Or) {
        *at += 1;
        left = Filterset::Or(Box::new(left), Box::new(parse_and(tokens, at)?));
    }
    Ok(left)
}

fn parse_and(tokens: &[FilterToken], at: &mut usize) -> Result<Filterset, String> {
    let mut left = parse_unary(tokens, at)?;
    loop {
        match tokens.get(*at) {
            Some(FilterToken::And) => {
                *at += 1;
                left = Filterset::And(Box::new(left), Box::new(parse_unary(tokens, at)?));
            }
            Some(FilterToken::Minus) => {
                *at += 1;
                let right = parse_unary(tokens, at)?;
                left = Filterset::And(Box::new(left), Box::new(Filterset::Not(Box::new(right))));
            }
            _ => return Ok(left),
        }
    }
}

fn parse_unary(tokens: &[FilterToken], at: &mut usize) -> Result<Filterset, String> {
    match tokens.get(*at) {
        Some(FilterToken::Not) => {
            *at += 1;
            Ok(Filterset::Not(Box::new(parse_unary(tokens, at)?)))
        }
        Some(FilterToken::Open) => {
            *at += 1;
            let inner = parse_or(tokens, at)?;
            if tokens.get(*at) != Some(&FilterToken::Close) {
                return Err("unbalanced parentheses in a filterset".to_string());
            }
            *at += 1;
            Ok(inner)
        }
        Some(FilterToken::Predicate(name, argument)) => {
            *at += 1;
            predicate(name, argument)
        }
        other => Err(format!("expected a filterset term, found {other:?}")),
    }
}

fn predicate(name: &str, argument: &str) -> Result<Filterset, String> {
    let matcher = |default_contains: bool| -> Result<Matcher, String> {
        if let Some(exact) = argument.strip_prefix('=') {
            return Ok(Matcher::Equal(exact.to_string()));
        }
        if let Some(needle) = argument.strip_prefix('~') {
            return Ok(Matcher::Contains(needle.to_string()));
        }
        if argument.starts_with('/') || argument.starts_with('#') {
            return Err(format!(
                "the matcher in `{name}({argument})` is not supported here"
            ));
        }
        if default_contains {
            return Ok(Matcher::Contains(argument.to_string()));
        }
        // The default for every non-`test` predicate is a GLOB; without a
        // metacharacter a glob is an exact match.
        if argument.contains(['*', '?', '[', '{']) {
            return Err(format!(
                "the glob in `{name}({argument})` is not supported here"
            ));
        }
        Ok(Matcher::Equal(argument.to_string()))
    };
    Ok(match name {
        "all" if argument.is_empty() => Filterset::All,
        "none" if argument.is_empty() => Filterset::None,
        "package" => Filterset::Package(matcher(false)?),
        "binary" => Filterset::Binary(matcher(false)?),
        "binary_id" => Filterset::BinaryId(matcher(false)?),
        "kind" => Filterset::Kind(matcher(false)?),
        "test" => Filterset::Test(matcher(true)?),
        _ => {
            return Err(format!(
                "the filterset predicate `{name}(...)` is not supported here"
            ));
        }
    })
}

/// Each nextest profile's `default-filter`, parsed. A profile without one inherits the
/// `default` profile's, as nextest's profiles do.
pub fn default_filters(config_text: &str) -> BTreeMap<String, Filterset> {
    let config: toml::Value = toml::from_str(config_text).expect("parsing .config/nextest.toml");
    let profiles = config
        .get("profile")
        .and_then(toml::Value::as_table)
        .expect("nextest.toml has profiles");
    let mut filters = BTreeMap::new();
    for (name, profile) in profiles {
        if let Some(expression) = profile.get("default-filter").and_then(toml::Value::as_str) {
            let parsed = parse_filterset(expression)
                .unwrap_or_else(|error| panic!("nextest profile `{name}` default-filter: {error}"));
            filters.insert(name.clone(), parsed);
        }
    }
    filters
}

/// The instant, in seconds after a test starts, at which nextest's slow-timeout kills it
/// under `profile`; `None` when the resolved slow-timeout carries no `terminate-after`
/// (nextest then only warns).
///
/// nextest resolves each setting from the first MATCHING override that SETS it: the
/// profile's own overrides in order, then the `default` profile's, which every profile
/// inherits and which outrank the profile's own `slow-timeout` (measured on nextest
/// 0.9.126: a `[[profile.default.overrides]]` kill of 1 s ended a test run under a
/// profile whose own `slow-timeout` allowed 40 s) — then the profile's `slow-timeout`,
/// then the `default` profile's. An override with no `filter` (a `platform`-only one) is
/// REFUSED rather than guessed.
pub fn kill_secs(config: &toml::Value, profile: &str, test: &TestIdentity<'_>) -> Option<u64> {
    let profiles = config
        .get("profile")
        .and_then(toml::Value::as_table)
        .expect("nextest.toml has profiles");
    let mut chain = Vec::new();
    if profile != "default" {
        chain.push(profile);
    }
    chain.push("default");
    for name in &chain {
        let overrides = profiles
            .get(*name)
            .and_then(|table| table.get("overrides"))
            .and_then(toml::Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        for entry in overrides {
            let Some(slow) = entry.get("slow-timeout") else {
                continue;
            };
            let expression = entry
                .get("filter")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("a `{name}` override without a `filter`: {entry}"));
            let filter = parse_filterset(expression)
                .unwrap_or_else(|error| panic!("a `{name}` override's filter: {error}"));
            if filter.matches(test) {
                return slow_timeout_kill(slow);
            }
        }
    }
    chain
        .iter()
        .find_map(|name| profiles.get(*name)?.get("slow-timeout"))
        .and_then(slow_timeout_kill)
}

/// `period` x `terminate-after`, in seconds; `None` for a bare period (no kill).
pub fn slow_timeout_kill(value: &toml::Value) -> Option<u64> {
    if value.is_str() {
        return None;
    }
    let period = value
        .get("period")
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("a slow-timeout without a `period`: {value}"));
    let terminate_after = value
        .get("terminate-after")?
        .as_integer()
        .unwrap_or_else(|| {
            panic!("a slow-timeout whose `terminate-after` is not an integer: {value}")
        });
    let terminate_after =
        u64::try_from(terminate_after).expect("`terminate-after` is a positive count");
    Some(duration_secs(period) * terminate_after)
}

/// A nextest duration in whole seconds: `"<n>s"` or `"<n>m"`. Anything else is refused.
pub fn duration_secs(text: &str) -> u64 {
    let (number, unit) = text.split_at(text.find(|c: char| !c.is_ascii_digit()).unwrap_or(0));
    let number: u64 = number
        .parse()
        .unwrap_or_else(|_| panic!("unsupported nextest duration `{text}`"));
    match unit {
        "s" => number,
        "m" => number * 60,
        _ => panic!("unsupported nextest duration `{text}`"),
    }
}
