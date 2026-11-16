//! Shared secret-redaction primitive.
//!
//! One canonical marker for a value that is intentionally NOT representable in a
//! log line, operator projection, or diagnostic — the single source of truth for
//! the placeholder every redaction site emits, so a leakage scan has exactly one
//! sentinel to look for and exactly one to assert is absent.
//!
//! Two adjacent disciplines share this module because they are the same rule
//! on different inputs: a VENDOR-CONTROLLED string is bounded ([`elide`])
//! before it may land on a durable or diagnostic surface,
//! and a LIFTED secret VALUE is replaced ([`scrub_secret_values`]) wherever a
//! vendor-influenced string could have carried it.
//!
//! The two compose in ONE order — scrub first, cut second — because a cut
//! that halves a lifted value leaves a fragment no whole-value scrub can
//! match. [`LiftedSecrets`] makes that order the only one an adapter or the
//! worker can take: [`LiftedSecrets::bound`] and [`LiftedSecrets::bound_field`]
//! scrub before they bound, and [`LiftedSecrets::cut`] also drops a kept
//! SUFFIX that is a proper prefix of a lifted value, so a value straddling
//! the boundary leaves nothing on the durable side. The set is an opaque,
//! redaction-only handle — its `Debug` prints a count, never a value, and
//! nothing on the type renders or transmits it.

/// The canonical placeholder a redacted secret VALUE is replaced by.
/// Deliberately a fixed, recognizable, non-secret token so a leakage scan can
/// assert both its presence (redaction happened) and the absence of the real
/// secret.
pub const REDACTED_PLACEHOLDER: &str = "[redacted]";

/// The byte bound ONE vendor-controlled string gets on a kata-owned surface —
/// a refusal reason, an evidence line, a warn log, a durable `worker_reason`
/// row. The line codecs bound a whole frame one layer up; this is the bound a
/// substring of one gets, so "the vendor said" can never grow a durable row.
pub const VENDOR_STRING_BYTES: usize = 240;

/// The first [`VENDOR_STRING_BYTES`] of a vendor-controlled string,
/// backtick-quoted and ending on a char boundary. A longer string is cut and
/// marked with its true length, so the difference between "the vendor said
/// this" and "the vendor flooded" is itself stated.
#[must_use]
pub fn elide(frame: &str) -> String {
    if frame.len() <= VENDOR_STRING_BYTES {
        return format!("`{frame}`");
    }
    let mut end = VENDOR_STRING_BYTES;
    while end > 0 && !frame.is_char_boundary(end) {
        end -= 1;
    }
    format!("`{}…` ({} bytes total)", &frame[..end], frame.len())
}

/// Replace every occurrence of a lifted secret VALUE in `text` with
/// [`REDACTED_PLACEHOLDER`].
///
/// `secrets` are the raw lifted values — an env var's contents, a lifted
/// token, a secret file's bytes as lossy text. Empty values are skipped (a
/// zero-length pattern would corrupt the text, not redact it); every other
/// value is scrubbed verbatim however short, because over-redaction mangles a
/// diagnostic and under-redaction lands a credential in a durable row — only
/// one of those is safe.
///
/// The occurrences are found in `text` as given, all at once, never in a
/// partly scrubbed text: a run of overlapping occurrences — a value nested in
/// a longer one, two values sharing bytes, a value overlapping itself — is
/// one placeholder, so no byte of any occurrence survives whatever order the
/// set holds its values in. A placeholder is never scanned, so a value the
/// placeholder itself contains (`]`, `d]`) is scrubbed like any other and no
/// value is refused.
#[must_use]
pub fn scrub_secret_values(text: &str, secrets: &[String]) -> String {
    let mut scrubbed = String::with_capacity(text.len());
    let mut from = 0;
    for covered in covered_runs(text, secrets) {
        scrubbed.push_str(&text[from..covered.start]);
        scrubbed.push_str(REDACTED_PLACEHOLDER);
        from = covered.end;
    }
    scrubbed.push_str(&text[from..]);
    scrubbed
}

/// The byte ranges of `text` an occurrence of a non-empty value covers, every
/// occurrence counted (overlapping ones too) and each run of overlapping
/// occurrences merged into one range, in order. Two occurrences that only
/// touch stay two ranges, so `TOKENTOKEN` is two placeholders.
fn covered_runs(text: &str, secrets: &[String]) -> Vec<std::ops::Range<usize>> {
    let mut occurrences: Vec<std::ops::Range<usize>> = Vec::new();
    for value in secrets.iter().filter(|value| !value.is_empty()) {
        let mut from = 0;
        while let Some(at) = text[from..].find(value.as_str()) {
            let start = from + at;
            occurrences.push(start..start + value.len());
            // A match starts on a char boundary; the next search starts on the
            // next one, so a value overlapping itself is found again.
            from = start + text[start..].chars().next().map_or(1, char::len_utf8);
        }
    }
    occurrences.sort_by_key(|occurrence| occurrence.start);
    let mut runs: Vec<std::ops::Range<usize>> = Vec::new();
    for occurrence in occurrences {
        match runs.last_mut() {
            Some(run) if occurrence.start < run.end => run.end = run.end.max(occurrence.end),
            _ => runs.push(occurrence),
        }
    }
    runs
}

/// One attempt's lifted credential VALUES, owned and cheap to share.
///
/// The ordering rule this type exists to state: a vendor-influenced string is
/// scrubbed against these values BEFORE any cut, on every kata surface. The
/// pre-slice-3 pipeline ran [`elide`] first and [`scrub_secret_values`] on the
/// fragment, which is the one order that leaks: a lifted value straddling the
/// [`VENDOR_STRING_BYTES`] cut survives as an unrecognised prefix — up to 239
/// bytes of a credential — in the durable reason or evidence field. Every
/// method here scrubs first; `cut` additionally drops the surviving PREFIX
/// fragment so a value that straddles an arbitrary caller bound leaves no
/// residue either.
///
/// `Debug` reports a COUNT, never a value: the set is handed to adapters and
/// the attempt scope for redaction only, and a value printed even once — a
/// panic message, a `dbg!` — lands in a log the scrub never reaches.
#[derive(Clone)]
pub struct LiftedSecrets(std::sync::Arc<[String]>);

impl LiftedSecrets {
    /// The empty set — nothing lifts, nothing scrubs.
    #[must_use]
    pub fn none() -> Self {
        Self(std::sync::Arc::from([]))
    }

    /// Take the lifted values, e.g. a resolved credential's `lifted_values()`.
    #[must_use]
    pub fn new(values: Vec<String>) -> Self {
        Self(std::sync::Arc::from(values))
    }

    /// Whether the set is empty — the common credential-less turn.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `text` with every lifted value replaced by [`REDACTED_PLACEHOLDER`].
    ///
    /// This is [`scrub_secret_values`]'s discipline over the owned set.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        scrub_secret_values(text, &self.0)
    }

    /// [`elide`] of [`scrub`](Self::scrub) — the quoted prose form, for
    /// refusal reasons and evidence suffixes. The scrub runs FIRST.
    #[must_use]
    pub fn bound(&self, text: &str) -> String {
        elide(&self.scrub(text))
    }

    /// The unquoted structured-field form: scrubbed, then kept whole when it
    /// fits [`VENDOR_STRING_BYTES`], else cut at a char boundary and marked
    /// with the true length — the same "flooded is stated" convention as
    /// [`elide`], minus the quoting a structured field does not want.
    #[must_use]
    pub fn bound_field(&self, text: &str) -> smol_str::SmolStr {
        let scrubbed = self.scrub(text);
        if scrubbed.len() <= VENDOR_STRING_BYTES {
            return smol_str::SmolStr::new(scrubbed);
        }
        let mut end = VENDOR_STRING_BYTES;
        while end > 0 && !scrubbed.is_char_boundary(end) {
            end -= 1;
        }
        smol_str::SmolStr::new(format!(
            "{}… ({} bytes total)",
            &scrubbed[..end],
            scrubbed.len()
        ))
    }

    /// Drop `text`'s trailing fragment: the longest non-empty suffix that is a
    /// PROPER PREFIX of a lifted value — repeatedly, because the suffix
    /// beneath a dropped fragment can itself be one.
    ///
    /// [`cut`](Self::cut) runs this on what it keeps, and a caller whose input
    /// a RAW cut already shortened (the adapters' `output_bytes` accumulators,
    /// the stderr drain's spool) runs it directly: the whole-value scrub
    /// cannot match the fragment a raw cut left at the tail, so the fragment
    /// is identified by shape and dropped. A straddling value leaves NOTHING
    /// on the surface, which is what makes the durable text safe to show at
    /// all.
    #[must_use]
    pub fn drop_trailing_fragment<'t>(&self, text: &'t str) -> &'t str {
        let mut kept = text;
        loop {
            match self.trailing_fragment_len(kept) {
                0 => break,
                len => kept = &kept[..kept.len() - len],
            }
        }
        kept
    }

    /// The byte length of `text`'s longest non-empty suffix that is a prefix
    /// of a lifted value, or `0` — the fragment a value straddling the end of
    /// `text` leaves behind. On SCRUBBED text no value is whole, so the suffix
    /// is a proper prefix and its length at most the longest value's, minus
    /// one. The suffix starts on a char boundary of `text`: it equals a value's
    /// leading bytes, which begin with a char's first byte.
    fn trailing_fragment_len(&self, text: &str) -> usize {
        self.0
            .iter()
            .filter(|value| !value.is_empty())
            .filter_map(|value| {
                (1..=value.len().min(text.len()))
                    .rev()
                    .find(|&len| value.is_char_boundary(len) && text.ends_with(&value[..len]))
            })
            .max()
            .unwrap_or(0)
    }

    /// The byte length of RAW `text`'s longest suffix that is a non-empty
    /// PROPER prefix of a lifted value, or `0` — the head of an occurrence a
    /// later piece could still finish. A suffix that is a whole value and
    /// begins no longer one is an occurrence already, not a head.
    fn unfinished_head_len(&self, text: &str) -> usize {
        self.0
            .iter()
            .filter_map(|value| {
                (1..value.len().min(text.len() + 1))
                    .rev()
                    .find(|&len| value.is_char_boundary(len) && text.ends_with(&value[..len]))
            })
            .max()
            .unwrap_or(0)
    }

    /// Scrub, then cut to at most `max_bytes` on a char boundary. Returns the
    /// kept text and whether the cut ran.
    ///
    /// When it cut, the kept text's trailing run is examined for a PREFIX of a
    /// lifted value via [`drop_trailing_fragment`](Self::drop_trailing_fragment):
    /// the scrub leaves the head of a value straddling the cut unrecognised,
    /// so the kept text's longest non-empty suffix that is a proper prefix of
    /// any lifted value is dropped.
    #[must_use]
    pub fn cut(&self, text: &str, max_bytes: usize) -> (String, bool) {
        let scrubbed = self.scrub(text);
        if scrubbed.len() <= max_bytes {
            return (scrubbed, false);
        }
        let mut end = max_bytes;
        while end > 0 && !scrubbed.is_char_boundary(end) {
            end -= 1;
        }
        (
            self.drop_trailing_fragment(&scrubbed[..end]).to_owned(),
            true,
        )
    }
}

/// A scrub that rolls across the pieces of ONE stream — a model's text
/// deltas — so a lifted value the stream splits across pieces is replaced
/// whole, never released as fragments no single piece's scrub can match.
///
/// [`push`](Self::push) appends a piece to the RAW text it still holds and
/// splits the whole at the start of the tail a later piece could still turn
/// into an occurrence: the earliest suffix that is a non-empty PROPER prefix
/// of a lifted value. No occurrence the stream has not finished starts
/// before the split, so a run of occurrences starting at or before it starts
/// where it will always start: its placeholder is released then, once, and
/// the bytes of the run past the split are held raw only so a later
/// occurrence overlapping them joins the run rather than opening another.
/// Everything else before the split is released as it is — the occurrences
/// found, as [`scrub_secret_values`] finds them, on the raw text, never on a
/// placeholder — and the tail stays raw. The held text is therefore at most
/// the longest value's length minus one bytes however long a run of
/// repeated values grows, and the released texts read back as the whole
/// stream's scrub: a released text carries no byte of an occurrence,
/// whatever values the set holds and however they overlap. What the
/// stream's end still holds is never released — it is at most an unfinished
/// value's head and the bytes of a run already placeheld, and a straddling
/// value leaves NOTHING on the surface, the same rule as
/// [`LiftedSecrets::cut`].
///
/// `Debug` reports how many bytes it holds, never the bytes: the held tail
/// may be a value's head.
#[derive(Default)]
pub struct RollingScrub {
    held: String,
    /// The length of `held`'s leading bytes a run whose placeholder is
    /// already released covers; an occurrence starting inside them joins
    /// that run.
    placeheld: usize,
}

impl RollingScrub {
    /// Append `piece` and release the scrubbed text no later piece can turn
    /// into a lifted value — possibly empty, when all of it could still be
    /// one's head or the run already released continues.
    #[must_use]
    pub fn push(&mut self, secrets: &LiftedSecrets, piece: &str) -> String {
        if secrets.is_empty() {
            return piece.to_owned();
        }
        self.held.push_str(piece);
        let split = self.held.len() - secrets.unfinished_head_len(&self.held);
        let mut runs = covered_runs(&self.held, &secrets.0).into_iter().peekable();
        let mut released = String::new();
        let mut from = 0;
        if self.placeheld > 0 {
            let mut end = self.placeheld;
            while let Some(run) = runs.next_if(|run| run.start < end) {
                end = end.max(run.end);
            }
            from = end;
        }
        // A run starting at or before the split starts there for good: no
        // occurrence a later piece finishes can start before the split.
        while let Some(run) = runs.next_if(|run| run.start <= split) {
            released.push_str(&self.held[from..run.start]);
            released.push_str(REDACTED_PLACEHOLDER);
            from = run.end;
        }
        if from < split {
            released.push_str(&self.held[from..split]);
        }
        self.placeheld = from.saturating_sub(split);
        self.held.drain(..split);
        released
    }
}

impl std::fmt::Debug for RollingScrub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RollingScrub({} byte(s) held)", self.held.len())
    }
}

impl std::fmt::Debug for LiftedSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LiftedSecrets({} value(s))", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_is_fixed_and_non_empty() {
        assert_eq!(REDACTED_PLACEHOLDER, "[redacted]");
    }

    #[test]
    fn elide_keeps_a_short_string_whole_and_bounds_a_long_one() {
        assert_eq!(elide("short complaint"), "`short complaint`");
        let long = "v".repeat(VENDOR_STRING_BYTES * 4);
        let elided = elide(&long);
        assert!(
            elided.starts_with('`')
                && elided.contains('…')
                && elided.contains(&format!("{} bytes total", long.len())),
            "the elision states the true length: {elided}"
        );
        // The kept prefix never exceeds the bound (allow the closing marker).
        assert!(elided.len() < VENDOR_STRING_BYTES + 80);
        // And the prefix is the FRAME's bytes — an elision that kept nothing
        // names a length it never showed.
        assert!(
            elided.contains(&"v".repeat(VENDOR_STRING_BYTES - 32)),
            "the kept bytes are the vendor's, not an empty prefix: {elided}"
        );
    }

    #[test]
    fn elide_ends_on_a_char_boundary() {
        // A multibyte char straddling the cut must not split — the bound moves
        // LEFT, never right: the kept prefix ends at 239, before the `☃` whose
        // bytes 239..242 straddle 240. An elision that stepped the bound the
        // other way keeps the char it claimed to cut.
        let mut frame = "a".repeat(VENDOR_STRING_BYTES - 1);
        frame.push('☃');
        frame.push_str(&"b".repeat(64));
        let elided = elide(&frame);
        assert!(elided.contains(&format!("{} bytes total", frame.len())));
        assert!(
            !elided.contains('☃'),
            "the straddling char is cut, not kept — the bound moves left: {elided}"
        );
        assert!(
            elided.starts_with(&format!("`{}", "a".repeat(VENDOR_STRING_BYTES - 1))),
            "the kept prefix is the bytes before the straddle: {elided}"
        );
    }

    #[test]
    fn scrub_secret_values_replaces_lifted_tokens_and_skips_the_empty() {
        let secrets = vec![
            "sk-lifted-7f3a".to_string(),
            String::new(),
            "acct-9".to_string(),
        ];
        let text = "the vendor echoed sk-lifted-7f3a and sk-lifted-7f3a and acct-9, loudly";
        let scrubbed = scrub_secret_values(text, &secrets);
        assert!(!scrubbed.contains("sk-lifted-7f3a") && !scrubbed.contains("acct-9"));
        assert_eq!(scrubbed.matches(REDACTED_PLACEHOLDER).count(), 3);
        // The empty value did not turn the text into placeholders.
        assert!(scrubbed.contains("the vendor echoed "));
    }

    #[test]
    fn lifted_secrets_debug_reports_a_count_never_a_value() {
        let secrets = LiftedSecrets::new(vec!["sk-very-secret-9f8a2c".to_string()]);
        let rendered = format!("{secrets:?}");
        assert_eq!(rendered, "LiftedSecrets(1 value(s))");
        assert!(
            !rendered.contains("9f8a2c"),
            "Debug must never print a lifted value: {rendered}"
        );
        assert!(LiftedSecrets::none().is_empty());
    }

    #[test]
    fn lifted_secrets_bound_scrubs_before_it_elides() {
        // The order is the property: elide-first leaves the token's head in the
        // kept prefix; scrub-first names the whole value `[redacted]` whether
        // or not the frame is cut.
        let token = "sk-straddle-0123456789abcdef";
        let secrets = LiftedSecrets::new(vec![token.to_string()]);
        let short = format!("the vendor said {token} plainly");
        let bounded = secrets.bound(&short);
        assert!(
            bounded.contains(REDACTED_PLACEHOLDER) && !bounded.contains("0123456789abcdef"),
            "the quoted form scrubs: {bounded}"
        );
        // A token straddling the 240-byte cut — neither the whole token nor any
        // run of its bytes may land.
        let mut frame = "a".repeat(220);
        frame.push_str(token);
        frame.push_str(&"b".repeat(80));
        let bounded = secrets.bound(&frame);
        assert!(
            !bounded.contains(&token[..12]),
            "no straddling fragment survives the quoted bound: {bounded}"
        );
    }

    #[test]
    fn lifted_secrets_bound_field_is_unquoted_and_bounded() {
        let token = "sk-field-0123456789abcdef";
        let secrets = LiftedSecrets::new(vec![token.to_string()]);
        // Short: verbatim, no quotes.
        let short = secrets.bound_field("session/prompt");
        assert_eq!(short.as_str(), "session/prompt");
        // Long: first bytes at a char boundary, marked with the true length —
        // no backticks a structured field does not want.
        let long = "m".repeat(VENDOR_STRING_BYTES * 4);
        let field = secrets.bound_field(&long);
        assert!(
            field.starts_with(&"m".repeat(VENDOR_STRING_BYTES - 8))
                && field.contains(&format!("{} bytes total", long.len()))
                && !field.contains('`'),
            "a long field is cut left, marked, unquoted: {field}"
        );
        // Secret-bearing: scrubbed before the cut, straddle fragment dropped.
        let mut text = "x".repeat(230);
        text.push_str(token);
        text.push_str("tail");
        let field = secrets.bound_field(&text);
        assert!(
            field.contains(REDACTED_PLACEHOLDER) && !field.contains(&token[..12]),
            "the field carries the placeholder, not a fragment: {field}"
        );
    }

    #[test]
    fn lifted_secrets_cut_drops_a_straddling_token_entirely() {
        let token = "sk-cut-straddle-0123456789abcdef0123456789";
        let secrets = LiftedSecrets::new(vec![token.to_string()]);
        // Token starts at byte 220; a 240-byte bound keeps only its head.
        let mut text = "p".repeat(220);
        text.push_str(token);
        text.push_str(&"q".repeat(500));
        let (kept, cut) = secrets.cut(&text, 240);
        assert!(cut, "a 741-byte string over a 240 bound cut");
        assert!(
            kept.len() <= 240 && kept.starts_with(&"p".repeat(200)),
            "the kept prefix is the innocent head: {} bytes",
            kept.len()
        );
        assert!(
            !kept.contains(&token[..12]),
            "no 12-byte window of the token survives the cut: {kept}"
        );
        // The case only the fragment drop covers: the vendor's text itself
        // carries the token's HEAD — no whole value for the scrub to see —
        // and the cut would keep 10 bytes of it. An innocent trailing "tail"
        // sits before the fragment so the kept prefix is not all fragment.
        let mut partial = "r".repeat(200);
        partial.push_str(&token[..30]);
        partial.push_str(&"s".repeat(500));
        let (kept, cut) = secrets.cut(&partial, 220);
        assert!(cut);
        assert!(
            !kept.contains(&token[..12]),
            "a literal prefix fragment is dropped, not kept: {kept}"
        );
        assert!(
            kept.starts_with(&"r".repeat(200)),
            "the innocent head survives the fragment drop: {kept}"
        );
        // Under the bound, text passes whole and reports no cut — and an
        // innocent cut keeps every byte it can.
        let under = secrets.cut(&"p".repeat(100), 240);
        assert_eq!(under, ("p".repeat(100), false));
        let innocent = secrets.cut(&"z".repeat(500), 240);
        assert_eq!(innocent, ("z".repeat(240), true));
    }

    #[test]
    fn drop_trailing_fragment_drops_a_raw_cut_leftover_and_nothing_else() {
        let token = "sk-fragment-0123456789abcdef0123456789";
        let secrets = LiftedSecrets::new(vec![token.to_string()]);
        // The case the caller owns: an earlier RAW cut left the token's head
        // at the tail — the scrub saw nothing, so the shape drops it.
        let mut text = "r".repeat(200);
        text.push_str(&token[..30]);
        assert_eq!(
            secrets.drop_trailing_fragment(&text),
            "r".repeat(200).as_str(),
            "the trailing fragment drops, the innocent head keeps"
        );
        // Stacked: a second lifted value's head sits beneath the first drop —
        // the loop must not stop at one. The innocent head ends in 't', which
        // prefixes neither value.
        let second = "acct-fragment-99999";
        let secrets = LiftedSecrets::new(vec![token.to_string(), second.to_string()]);
        let mut text = "t".repeat(50);
        text.push_str(&second[..12]);
        text.push_str(&token[..30]);
        assert_eq!(
            secrets.drop_trailing_fragment(&text),
            "t".repeat(50).as_str(),
            "the fragment beneath a dropped fragment is itself dropped"
        );
        // The conservative edge, stated: a kept tail ending in a byte that is
        // a one-byte prefix of a lifted value is dropped too — the function
        // cannot tell an innocent 's' from a straddled secret's first byte,
        // and over-redaction is the safe direction when capture was already
        // exceeded.
        let mut text = "s".repeat(50);
        text.push_str(&token[..30]);
        assert_eq!(
            secrets.drop_trailing_fragment(&text),
            "",
            "a trailing byte that could be a value's head drops — the \\
             direction that cannot leak"
        );
        // A mid-text prefix and an innocent tail are left alone — the drop is
        // the TRAILING run only, and an empty set drops nothing.
        let mut text = "t".repeat(20);
        text.push_str(&token[..25]);
        text.push_str("tail");
        assert_eq!(
            secrets.drop_trailing_fragment(&text),
            text.as_str(),
            "a fragment mid-string is not the trailing run"
        );
        let text = "u".repeat(30);
        assert_eq!(LiftedSecrets::none().drop_trailing_fragment(&text), text);
    }

    /// **A rolling scrub releases a stream with every lifted value redacted
    /// whole, however the stream is split, and holds back less than a value.**
    /// Every way of cutting the stream into two or three pieces is pushed; the
    /// released texts concatenate to the whole stream with each value
    /// replaced, no released text carries two consecutive bytes of a value
    /// (the values share no 2-byte window with the rest of the stream), and
    /// after each push the released total trails what was pushed by at most
    /// the longest value's length minus one.
    ///
    /// **Would red if:** a piece were scrubbed alone (a split value leaves
    /// fragments), the held tail were dropped rather than carried (the
    /// read-back loses text), or the hold-back were wider than a value's head.
    #[test]
    fn rolling_scrub_redacts_a_value_at_every_split_and_holds_back_less_than_a_value() {
        let values = ["SECRET-ONE-☃-01", "XYZW"];
        let secrets = LiftedSecrets::new(values.iter().map(|value| (*value).to_owned()).collect());
        let stream = "lead SECRET-ONE-☃-01 mid XYZW tail SECRET-ONE-☃-01";
        let expected = "lead [redacted] mid [redacted] tail [redacted]";
        let longest = values.iter().map(|value| value.len()).max().unwrap();
        let bounds: Vec<usize> = (0..=stream.len())
            .filter(|at| stream.is_char_boundary(*at))
            .collect();
        let mut splits: Vec<Vec<usize>> = bounds.iter().map(|at| vec![*at]).collect();
        for (i, first) in bounds.iter().enumerate() {
            for second in &bounds[i..] {
                splits.push(vec![*first, *second]);
            }
        }
        for cuts in splits {
            let mut scrub = RollingScrub::default();
            let mut released = String::new();
            let mut from = 0;
            for end in cuts.iter().copied().chain([stream.len()]) {
                let piece = scrub.push(&secrets, &stream[from..end]);
                for value in values {
                    for window in value.as_bytes().windows(2) {
                        assert!(
                            !piece.as_bytes().windows(2).any(|bytes| bytes == window),
                            "{cuts:?}: a released piece carries bytes of {value}: {piece:?}"
                        );
                    }
                }
                released.push_str(&piece);
                let pushed = scrub_secret_values(
                    &stream[..end],
                    &values
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                );
                assert!(
                    released.len() + longest > pushed.len(),
                    "{cuts:?}: held back {} bytes, a value is {longest}",
                    pushed.len().saturating_sub(released.len())
                );
                from = end;
            }
            assert_eq!(
                released, expected,
                "{cuts:?}: the stream reads back redacted"
            );
        }
    }

    /// Every way of cutting `stream` into one, two or three pieces, as the
    /// cut offsets — every char boundary, in order.
    fn every_split(stream: &str) -> Vec<Vec<usize>> {
        let bounds: Vec<usize> = (0..=stream.len())
            .filter(|at| stream.is_char_boundary(*at))
            .collect();
        let mut splits: Vec<Vec<usize>> = vec![vec![]];
        for (i, first) in bounds.iter().enumerate() {
            splits.push(vec![*first]);
            for second in &bounds[i..] {
                splits.push(vec![*first, *second]);
            }
        }
        splits
    }

    /// `stream` pushed through one [`RollingScrub`] in the pieces `cuts`
    /// names: each released text, in order.
    fn roll(secrets: &LiftedSecrets, stream: &str, cuts: &[usize]) -> Vec<String> {
        let mut scrub = RollingScrub::default();
        let mut from = 0;
        cuts.iter()
            .copied()
            .chain([stream.len()])
            .map(|end| {
                let piece = scrub.push(secrets, &stream[from..end]);
                from = end;
                piece
            })
            .collect()
    }

    /// **A value nested inside a longer value is redacted with the longer one,
    /// whole, however the stream is split and in whichever order the set holds
    /// them.** The oracle is written here, not borrowed: the longest value
    /// replaced first over the whole stream. The rolling read-back equals it at
    /// every one-, two- and three-piece split, no released text carries a
    /// 4-byte window of either value, and the whole-stream scrub equals it for
    /// both orders of the set.
    ///
    /// **Would red if:** the hold-back were decided on the scrubbed text (the
    /// shorter value's placeholder hides the longer value's unfinished head,
    /// and its tail `-post` is released), or the whole-stream scrub replaced
    /// the shorter value first.
    #[test]
    fn rolling_scrub_redacts_a_nested_value_with_its_longer_value_at_every_split() {
        let stream = "say pre-TOKEN-post, TOKEN end";
        let reference = |values: &[&str]| {
            let mut longest_first = values.to_vec();
            longest_first.sort_by_key(|value| std::cmp::Reverse(value.len()));
            longest_first.iter().fold(stream.to_owned(), |text, value| {
                text.replace(value, "[redacted]")
            })
        };
        for values in [["pre-TOKEN-post", "TOKEN"], ["TOKEN", "pre-TOKEN-post"]] {
            let expected = reference(&values);
            assert_eq!(expected, "say [redacted], [redacted] end");
            let owned: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
            assert_eq!(
                scrub_secret_values(stream, &owned),
                expected,
                "{values:?}: the whole-stream scrub redacts the longer value whole"
            );
            let secrets = LiftedSecrets::new(owned);
            for cuts in every_split(stream) {
                let pieces = roll(&secrets, stream, &cuts);
                for piece in &pieces {
                    for value in values {
                        for window in value.as_bytes().windows(4) {
                            assert!(
                                !piece.as_bytes().windows(4).any(|bytes| bytes == window),
                                "{values:?} {cuts:?}: a released piece carries bytes of \
                                 {value}: {pieces:?}"
                            );
                        }
                    }
                }
                assert_eq!(
                    pieces.concat(),
                    expected,
                    "{values:?} {cuts:?}: the stream reads back as the reference scrub"
                );
            }
        }
    }

    /// **A run of overlapping occurrences is one placeholder, touching
    /// occurrences stay two, and the rolling read-back is the same at every
    /// split.** Two values sharing bytes (`ABC`, `CDEF` in `ABCDEF`) and a
    /// value overlapping itself (`ABAB` in `ABABAB`) leave no byte of either
    /// occurrence; `TOKENTOKEN` is two placeholders.
    ///
    /// **Would red if:** the scrub replaced one value at a time (`ABC` first
    /// leaves `[redacted]DEF`; `ABAB` replaced left to right leaves `AB`), or
    /// the rolling split could fall inside a run.
    #[test]
    fn overlapping_occurrences_are_one_placeholder_whole_and_rolling() {
        let cases: [(&[&str], &str, &str); 3] = [
            (&["ABC", "CDEF"], "x ABCDEF y", "x [redacted] y"),
            (&["ABAB"], "x ABABAB y", "x [redacted] y"),
            (&["TOKEN"], "x TOKENTOKEN y", "x [redacted][redacted] y"),
        ];
        for (values, stream, expected) in cases {
            let secrets =
                LiftedSecrets::new(values.iter().map(|value| (*value).to_owned()).collect());
            assert_eq!(
                secrets.scrub(stream),
                expected,
                "{values:?}: the whole stream"
            );
            for cuts in every_split(stream) {
                assert_eq!(
                    roll(&secrets, stream, &cuts).concat(),
                    expected,
                    "{values:?} {cuts:?}: the rolling read-back"
                );
            }
        }
    }

    /// **A value the placeholder itself contains is redacted like any other,
    /// and the placeholder is never held as its head.** `]` and `d]` are both
    /// inside `[redacted]`; at every split the stream reads back with each
    /// occurrence replaced once and nothing held at its end.
    ///
    /// **Would red if:** the hold-back were decided on the scrubbed text (the
    /// placeholder's closing `]` reads as a value's head and is held, rescrubbed
    /// and held again — the stream never ends) or a placeholder were scrubbed
    /// again.
    #[test]
    fn rolling_scrub_never_holds_or_rescrubs_its_own_placeholder() {
        let secrets = LiftedSecrets::new(vec!["]".to_owned(), "d]".to_owned()]);
        let stream = "a]b d] c]e]";
        let expected = "a[redacted]b [redacted] c[redacted]e[redacted]";
        assert_eq!(secrets.scrub(stream), expected);
        for cuts in every_split(stream) {
            let mut scrub = RollingScrub::default();
            let mut released = String::new();
            let mut from = 0;
            for end in cuts.iter().copied().chain([stream.len()]) {
                released.push_str(&scrub.push(&secrets, &stream[from..end]));
                from = end;
            }
            assert_eq!(
                released, expected,
                "{cuts:?}: the stream reads back redacted"
            );
            assert_eq!(
                format!("{scrub:?}"),
                "RollingScrub(0 byte(s) held)",
                "{cuts:?}: a stream ending on a whole value holds nothing"
            );
        }
    }

    /// **A coincidental value head is released once the stream leaves it, and
    /// an empty set holds nothing.** `XY` could begin `XYZW` and is held; the
    /// next piece shows it does not, and it is released in order. A stream's
    /// unfinished head is never released.
    #[test]
    fn rolling_scrub_releases_a_head_the_stream_abandons_and_holds_nothing_for_no_values() {
        let secrets = LiftedSecrets::new(vec!["XYZW".to_owned()]);
        let mut scrub = RollingScrub::default();
        assert_eq!(scrub.push(&secrets, "ab XY"), "ab ");
        assert_eq!(scrub.push(&secrets, "Q cd X"), "XYQ cd ");
        assert_eq!(scrub.push(&secrets, "YZ"), "");
        assert_eq!(
            format!("{scrub:?}"),
            "RollingScrub(3 byte(s) held)",
            "Debug counts the held bytes and never prints them"
        );
        let mut none = RollingScrub::default();
        assert_eq!(none.push(&LiftedSecrets::none(), "XY"), "XY");
        assert_eq!(format!("{none:?}"), "RollingScrub(0 byte(s) held)");
    }

    /// The byte count a [`RollingScrub`]'s `Debug` reports it holds.
    fn held_len(scrub: &RollingScrub) -> usize {
        let rendered = format!("{scrub:?}");
        rendered
            .strip_prefix("RollingScrub(")
            .and_then(|rest| rest.strip_suffix(" byte(s) held)"))
            .and_then(|count| count.parse().ok())
            .unwrap_or_else(|| panic!("an unexpected Debug: {rendered}"))
    }

    /// **A stream repeating a value back to back holds less than a value,
    /// however long the run grows.** `abab` overlaps itself, so `ababab…` is
    /// ONE run of occurrences that every push extends; 64 KiB of it, pushed
    /// three bytes at a time, reads back as one placeholder, and after every
    /// push the scrub holds at most the longest value's length minus one —
    /// so neither the held text nor a push's rescan of it grows with the
    /// stream.
    ///
    /// **Would red if:** an open run were held raw until it closed (the held
    /// text, and each push's rescan of it, grows with the run — quadratic in
    /// the stream), or the run's placeholder were released once per push.
    #[test]
    fn rolling_scrub_holds_less_than_a_value_through_a_run_of_repeated_values() {
        let values = ["abab", "XYZ☃"];
        let longest = values.iter().map(|value| value.len()).max().unwrap();
        let secrets = LiftedSecrets::new(values.iter().map(|value| (*value).to_owned()).collect());
        let stream = format!("x {} y", "ab".repeat(32 * 1024));
        let mut scrub = RollingScrub::default();
        let mut released = String::new();
        let mut from = 0;
        while from < stream.len() {
            let end = (from + 3).min(stream.len());
            released.push_str(&scrub.push(&secrets, &stream[from..end]));
            assert!(
                held_len(&scrub) < longest,
                "after {end} bytes the scrub holds {} bytes, a value is {longest}",
                held_len(&scrub)
            );
            from = end;
        }
        assert_eq!(released, "x [redacted] y");
    }

    /// **A run's placeholder is released on the push that settles where the
    /// run starts, and a value ending at the held tail is released whole on
    /// that push.** `TOKEN` ends where the head `XY` of `XYZW` begins: the
    /// push releases `a [redacted]` and holds `XY` alone. `ab` is whole and
    /// also the head of `abc`: no later piece can start an occurrence before
    /// it, so its placeholder is released at once and the run it may grow
    /// into (`abc`) adds no second one.
    ///
    /// **Would red if:** a run ending exactly at the held tail were held with
    /// it, or a whole occurrence starting exactly at the held tail were held
    /// raw rather than released as its placeholder.
    #[test]
    fn rolling_scrub_releases_a_run_on_the_push_that_settles_its_start() {
        let secrets = LiftedSecrets::new(vec!["TOKEN".to_owned(), "XYZW".to_owned()]);
        let mut scrub = RollingScrub::default();
        assert_eq!(scrub.push(&secrets, "a TOKENXY"), "a [redacted]");
        assert_eq!(held_len(&scrub), 2, "only the head XY is held");
        assert_eq!(scrub.push(&secrets, "Q"), "XYQ");

        let secrets = LiftedSecrets::new(vec!["ab".to_owned(), "abc".to_owned()]);
        let mut scrub = RollingScrub::default();
        assert_eq!(scrub.push(&secrets, "x ab"), "x [redacted]");
        assert_eq!(scrub.push(&secrets, "c y"), " y");
        assert_eq!(secrets.scrub("x abc y"), "x [redacted] y");
        let mut scrub = RollingScrub::default();
        assert_eq!(scrub.push(&secrets, "x ab"), "x [redacted]");
        assert_eq!(scrub.push(&secrets, "d"), "d");
        assert_eq!(secrets.scrub("x abd"), "x [redacted]d");

        let secrets = LiftedSecrets::new(vec!["abab".to_owned()]);
        let mut scrub = RollingScrub::default();
        assert_eq!(scrub.push(&secrets, "ababa"), "[redacted]");
        assert_eq!(
            scrub.push(&secrets, "b"),
            "",
            "the run grows; no second placeholder"
        );
        assert_eq!(scrub.push(&secrets, " y"), " y");
    }

    /// Deterministic splitmix64 step — the same seed draws the same case on
    /// every platform.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A reference scrub that shares no code with the module: every
    /// occurrence of every non-empty value found by testing each char
    /// boundary, sorted, and a run of occurrences each starting before the
    /// run so far ends replaced by one placeholder.
    fn reference_scrub(text: &str, values: &[String]) -> String {
        let mut occurrences: Vec<(usize, usize)> = (0..=text.len())
            .filter(|at| text.is_char_boundary(*at))
            .flat_map(|at| {
                values
                    .iter()
                    .filter(move |value| {
                        !value.is_empty() && text[at..].starts_with(value.as_str())
                    })
                    .map(move |value| (at, at + value.len()))
            })
            .collect();
        occurrences.sort_unstable();
        let mut out = String::new();
        let mut from = 0;
        let mut index = 0;
        while index < occurrences.len() {
            let (start, mut end) = occurrences[index];
            index += 1;
            while index < occurrences.len() && occurrences[index].0 < end {
                end = end.max(occurrences[index].1);
                index += 1;
            }
            out.push_str(&text[from..start]);
            out.push_str("[redacted]");
            from = end;
        }
        out.push_str(&text[from..]);
        out
    }

    /// The seeded cases [`rolling_scrub_reads_back_as_the_whole_stream_scrub_for_random_streams`] draws.
    const ROLLING_CASES: u64 = 20_000;

    /// **For random value sets and streams, pushed in random pieces, the
    /// releases read back as the whole stream's scrub and the scrub holds
    /// less than a value after every push.** Values are drawn short from a
    /// two-letter-plus-multibyte alphabet — so they overlap themselves and
    /// each other and prefix one another — streams splice values into
    /// random text, and pieces are cut at random char boundaries (one char
    /// at a time in a quarter of the cases). Each stream ends on `#`, a char
    /// no value holds, so the last push releases everything and the
    /// read-back is the whole stream; it must equal both
    /// [`LiftedSecrets::scrub`] and a reference written in the test.
    ///
    /// **Would red if:** a run were split across releases (two placeholders
    /// for one run, or a placeholder for a run a later piece moved), a
    /// value's head were released before the stream abandoned it, or the
    /// held text outgrew a value.
    #[test]
    fn rolling_scrub_reads_back_as_the_whole_stream_scrub_for_random_streams() {
        const ALPHABET: [&str; 5] = ["a", "b", "é", "☃", "c"];
        for seed in 0..ROLLING_CASES {
            let mut state = seed;
            let mut draw =
                |below: usize| usize::try_from(splitmix64(&mut state) % below as u64).unwrap();
            let mut values: Vec<String> = Vec::new();
            for _ in 0..=draw(3) {
                let value: String = if !values.is_empty() && draw(3) == 0 {
                    let base: Vec<char> = values[draw(values.len())].chars().collect();
                    base[..=draw(base.len())].iter().collect()
                } else {
                    (0..=draw(4)).map(|_| ALPHABET[draw(3)]).collect()
                };
                values.push(value);
            }
            let mut stream = String::new();
            for _ in 0..draw(12) {
                if draw(2) == 0 {
                    stream.push_str(&values[draw(values.len())]);
                } else {
                    stream.push_str(ALPHABET[draw(ALPHABET.len())]);
                }
            }
            stream.push('#');
            let longest = values.iter().map(String::len).max().unwrap();
            let secrets = LiftedSecrets::new(values.clone());
            let one_char_pieces = draw(4) == 0;
            let mut scrub = RollingScrub::default();
            let mut released = String::new();
            let mut rest = stream.as_str();
            while !rest.is_empty() {
                let chars = rest.chars().count();
                let take = if one_char_pieces {
                    1
                } else {
                    1 + draw(chars.min(6))
                };
                let end = rest
                    .char_indices()
                    .nth(take)
                    .map_or(rest.len(), |(at, _)| at);
                released.push_str(&scrub.push(&secrets, &rest[..end]));
                assert!(
                    held_len(&scrub) < longest,
                    "seed {seed} {values:?} {stream:?}: holds {} bytes",
                    held_len(&scrub)
                );
                rest = &rest[end..];
            }
            let expected = reference_scrub(&stream, &values);
            assert_eq!(
                secrets.scrub(&stream),
                expected,
                "seed {seed} {values:?} {stream:?}"
            );
            assert_eq!(
                released, expected,
                "seed {seed} {values:?} {stream:?}: the read-back"
            );
            assert_eq!(
                held_len(&scrub),
                0,
                "seed {seed}: the closing `#` releases all"
            );
        }
    }
}
