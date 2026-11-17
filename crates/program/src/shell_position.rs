//! Where a shell stage's `run=` template places an emitted value: a POSIX shell
//! lexer over the template's LITERAL text, run by
//! [`crate::target_namespace::untrusted_reads_in_command`].
//!
//! `shquote` renders its value as `'…'`. That is one shell word only where the
//! shell reads a `'` as opening a quote of the command text — not inside `"…"`,
//! `'…'`, `$'…'`, a backtick substitution, `${…}`, `$((…))`, a comment or a
//! heredoc body (whatever its delimiter's quoting), and not right after an
//! unquoted `\` or `$` or as a heredoc's delimiter word.
//! [`ShellPosition::takes_one_word`] answers exactly that. Inside `$(…)` — in
//! any enclosing context but a backtick — the shell parses afresh, so a quoted
//! word is one word there.
//!
//! The lexer follows the literal text only. An expression's value is taken to
//! change no lexer state ([`ShellPosition::word`]): a `target` read that could
//! is refused unless it is quoted, and the other namespaces are not this rule's
//! subject. A position the lexer cannot follow is [`ShellPosition::unknown`],
//! where no word is one word:
//!
//! * a `case` word inside `$(…)` — a pattern's `)` would close it;
//! * a heredoc operator with no delimiter word, and a `\` inside a
//!   double-quoted delimiter.
//!
//! A heredoc whose delimiter or terminating line holds an expression's value
//! never ends: the lexer cannot tell which line ends it.

/// One construct the lexer is inside.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Open {
    /// `'…'`.
    Single,
    /// `$'…'`: a `\` escapes the next character.
    AnsiC,
    /// `"…"`.
    Double,
    /// `` `…` ``: the shell scans to the next unescaped backtick, quotes or not.
    Backtick,
    /// `$( … )`, with its open-parenthesis depth.
    Subst { depth: u32 },
    /// `$(( … ))`, with its open-parenthesis depth.
    Arith { depth: u32 },
    /// `${ … }`; inside `"…"` a `'` is literal.
    Brace { in_double: bool },
    /// `#` to the end of the line.
    Comment,
}

/// A heredoc's terminating line: `None` when an expression's value is part of
/// the delimiter, so no line is known to end it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Delimiter {
    word: Option<String>,
    strip_tabs: bool,
}

/// The delimiter word after `<<` / `<<-`, being read.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DelimiterScan {
    /// `None` once an expression's value is part of it.
    word: Option<String>,
    started: bool,
    strip_tabs: bool,
    quote: Option<char>,
    escaped: bool,
}

/// A heredoc body being read, line by line.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Body {
    delimiter: Delimiter,
    line: String,
    line_known: bool,
}

impl DelimiterScan {
    fn push(&mut self, c: char) {
        if let Some(word) = &mut self.word {
            word.push(c);
        }
    }
}

/// What a `$` leaves: `$$` is a parameter, not the start of another.
const fn dollar_after(was_dollar: bool) -> After {
    if was_dollar {
        After::Nothing
    } else {
        After::Dollar
    }
}

impl Body {
    fn new(delimiter: Delimiter) -> Self {
        Self {
            delimiter,
            line: String::new(),
            line_known: true,
        }
    }
}

/// What the previous character makes of the next one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum After {
    #[default]
    Nothing,
    /// A `\` that escapes it.
    Backslash,
    /// A `$` that may begin an expansion with it.
    Dollar,
    /// `$(`: a `(` makes it `$((`.
    SubstOpen,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Lexer {
    open: Vec<Open>,
    after: After,
    /// The next character begins a token (so a `#` begins a comment).
    word_start: bool,
    /// The unquoted characters of the current word, for `case`.
    word: String,
    /// Consecutive unquoted `<` just read.
    angles: u8,
    scan: Option<DelimiterScan>,
    /// Heredocs whose bodies begin at the next newline, in order.
    pending: Vec<Delimiter>,
    body: Option<Body>,
}

/// One place in the shell text, or [`Self::unknown`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ShellPosition(Option<Lexer>);

impl ShellPosition {
    /// The start of a command text.
    pub(crate) fn start() -> Self {
        Self(Some(Lexer {
            open: Vec::new(),
            after: After::Nothing,
            word_start: true,
            word: String::new(),
            angles: 0,
            scan: None,
            pending: Vec::new(),
            body: None,
        }))
    }

    /// A position the lexer cannot follow: no word is one word there.
    pub(crate) const fn unknown() -> Self {
        Self(None)
    }

    pub(crate) const fn is_unknown(&self) -> bool {
        self.0.is_none()
    }

    /// Whether a `'…'` emitted here is one shell word: the shell reads its `'`
    /// as opening a quote of the command text.
    pub(crate) fn takes_one_word(&self) -> bool {
        self.0.as_ref().is_some_and(|lexer| {
            matches!(lexer.open.last(), None | Some(Open::Subst { .. }))
                && !lexer.open.contains(&Open::Backtick)
                && !matches!(lexer.after, After::Backslash | After::Dollar)
                && lexer.angles < 2
                && lexer.scan.is_none()
                && lexer.body.is_none()
        })
    }

    /// Advance over literal template text.
    pub(crate) fn raw(&mut self, text: &str) {
        for c in text.chars() {
            let Some(lexer) = &mut self.0 else { return };
            if !lexer.feed(c) {
                self.0 = None;
            }
        }
    }

    /// Advance over an expression's value, taken as word text that changes no
    /// lexer state.
    pub(crate) fn word(&mut self) {
        if let Some(lexer) = &mut self.0 {
            lexer.word();
        }
    }

    /// Advance over a `shquote` output. Where it is one word it leaves the
    /// lexer as `''` would; anywhere else its value's own quotes decide what
    /// follows, so the position is lost.
    pub(crate) fn quoted_word(&mut self) {
        if self.takes_one_word() {
            self.raw("''");
        } else {
            self.0 = None;
        }
    }
}

impl Lexer {
    /// Read `c`; `false` when the lexer can no longer follow the text.
    fn feed(&mut self, c: char) -> bool {
        if self.body.is_some() {
            self.feed_body(c);
            return true;
        }
        if self.scan.is_some() {
            return self.feed_delimiter(c);
        }
        let after = std::mem::take(&mut self.after);
        if after == After::Backslash {
            self.word_start = false;
            self.word.push(c);
            return true;
        }
        match self.open.last().cloned() {
            None | Some(Open::Subst { .. }) => return self.feed_plain(c, after),
            Some(Open::Comment) => {
                if c == '\n' {
                    self.open.pop();
                    return self.feed_plain(c, After::Nothing);
                }
            }
            Some(Open::Single) => {
                if c == '\'' {
                    self.open.pop();
                }
            }
            Some(Open::AnsiC) => match c {
                '\\' => self.after = After::Backslash,
                '\'' => {
                    self.open.pop();
                }
                _ => {}
            },
            Some(Open::Backtick) => match c {
                '\\' => self.after = After::Backslash,
                '`' => {
                    self.open.pop();
                }
                _ => {}
            },
            Some(Open::Arith { depth }) => match c {
                '(' => self.set_depth(depth + 1),
                ')' => self.set_depth(depth - 1),
                _ => {}
            },
            Some(Open::Double) => {
                let was_dollar = after == After::Dollar;
                if was_dollar && self.expansion(c, true) {
                    return true;
                }
                match c {
                    '"' => {
                        self.open.pop();
                    }
                    '\\' => self.after = After::Backslash,
                    '`' => self.open.push(Open::Backtick),
                    '$' => self.after = dollar_after(was_dollar),
                    _ => {}
                }
            }
            Some(Open::Brace { in_double }) => {
                let was_dollar = after == After::Dollar;
                if was_dollar && self.expansion(c, in_double) {
                    return true;
                }
                match c {
                    '}' => {
                        self.open.pop();
                    }
                    '\\' => self.after = After::Backslash,
                    '"' => self.open.push(Open::Double),
                    '\'' if !in_double => self.open.push(Open::Single),
                    '`' => self.open.push(Open::Backtick),
                    '$' => self.after = dollar_after(was_dollar),
                    _ => {}
                }
            }
        }
        true
    }

    /// Set the innermost `$((`'s depth, closing it at zero.
    fn set_depth(&mut self, depth: u32) {
        if depth == 0 {
            self.open.pop();
        } else if let Some(Open::Arith { depth: open }) = self.open.last_mut() {
            *open = depth;
        }
    }

    /// `c` after an unescaped `$`: the expansion it opens, if any. `quoted`
    /// inside `"…"`, where `$'` and `$"` are literal.
    fn expansion(&mut self, c: char, quoted: bool) -> bool {
        let open = match c {
            '(' => {
                self.after = After::SubstOpen;
                self.word.clear();
                Open::Subst { depth: 1 }
            }
            '{' => Open::Brace { in_double: quoted },
            '\'' if !quoted => Open::AnsiC,
            '"' if !quoted => Open::Double,
            _ => return false,
        };
        self.open.push(open);
        self.word_start = false;
        true
    }

    /// `c` in the command text itself (or inside `$( … )`).
    fn feed_plain(&mut self, c: char, after: After) -> bool {
        if after == After::SubstOpen && c == '(' {
            self.open.pop();
            self.open.push(Open::Arith { depth: 2 });
            return true;
        }
        let was_dollar = after == After::Dollar;
        if was_dollar && self.expansion(c, false) {
            return true;
        }
        if c == '<' {
            self.angles = self.angles.saturating_add(1);
            return self.end_word();
        }
        if std::mem::take(&mut self.angles) == 2 {
            self.scan = Some(DelimiterScan {
                word: Some(String::new()),
                started: false,
                strip_tabs: c == '-',
                quote: None,
                escaped: false,
            });
            return c == '-' || self.feed_delimiter(c);
        }
        match c {
            '\\' => {
                self.after = After::Backslash;
                self.word_start = false;
            }
            '\'' => self.push_word(Open::Single),
            '"' => self.push_word(Open::Double),
            '`' => self.push_word(Open::Backtick),
            '$' => {
                self.after = dollar_after(was_dollar);
                self.word_start = false;
            }
            '#' if self.word_start => self.open.push(Open::Comment),
            '\n' => {
                if !self.end_word() {
                    return false;
                }
                if !self.pending.is_empty() {
                    self.body = Some(Body::new(self.pending.remove(0)));
                }
            }
            ' ' | '\t' | ';' | '&' | '|' | '>' => return self.end_word(),
            '(' => {
                if let Some(Open::Subst { depth }) = self.open.last_mut() {
                    *depth += 1;
                }
                return self.end_word();
            }
            ')' => {
                if let Some(Open::Subst { depth }) = self.open.last_mut() {
                    *depth -= 1;
                    if *depth == 0 {
                        self.open.pop();
                    }
                }
                return self.end_word();
            }
            _ => {
                self.word_start = false;
                self.word.push(c);
            }
        }
        true
    }

    fn push_word(&mut self, open: Open) {
        self.open.push(open);
        self.word_start = false;
    }

    /// A token ends: refuse to follow a `case` inside `$( … )`.
    fn end_word(&mut self) -> bool {
        self.word_start = true;
        let word = std::mem::take(&mut self.word);
        !(word == "case"
            && self
                .open
                .iter()
                .any(|open| matches!(open, Open::Subst { .. })))
    }

    fn feed_delimiter(&mut self, c: char) -> bool {
        let Some(scan) = &mut self.scan else {
            return true;
        };
        if std::mem::take(&mut scan.escaped) {
            scan.push(c);
            return true;
        }
        if let Some(quote) = scan.quote {
            match c {
                '\\' if quote == '"' => return false,
                _ if c == quote => scan.quote = None,
                _ => scan.push(c),
            }
            return true;
        }
        match c {
            ' ' | '\t' if !scan.started => {}
            ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')' => {
                if !scan.started {
                    return false;
                }
                let delimiter = Delimiter {
                    word: scan.word.take(),
                    strip_tabs: scan.strip_tabs,
                };
                self.scan = None;
                self.pending.push(delimiter);
                return self.feed_plain(c, After::Nothing);
            }
            '\\' => {
                scan.escaped = true;
                scan.started = true;
            }
            '\'' | '"' => {
                scan.quote = Some(c);
                scan.started = true;
            }
            _ => {
                scan.push(c);
                scan.started = true;
            }
        }
        true
    }

    fn feed_body(&mut self, c: char) {
        let Some(body) = &mut self.body else { return };
        if c != '\n' {
            body.line.push(c);
            return;
        }
        let line = if body.delimiter.strip_tabs {
            body.line.trim_start_matches('\t')
        } else {
            body.line.as_str()
        };
        let ends = body.line_known && body.delimiter.word.as_deref() == Some(line);
        body.line.clear();
        body.line_known = true;
        if ends {
            self.body = (!self.pending.is_empty()).then(|| Body::new(self.pending.remove(0)));
            self.word_start = true;
        }
    }

    fn word(&mut self) {
        if let Some(body) = &mut self.body {
            body.line_known = false;
            return;
        }
        if let Some(scan) = &mut self.scan {
            scan.word = None;
            scan.started = true;
            return;
        }
        if std::mem::take(&mut self.angles) == 2 {
            self.scan = Some(DelimiterScan {
                word: None,
                started: true,
                strip_tabs: false,
                quote: None,
                escaped: false,
            });
            return;
        }
        self.after = After::Nothing;
        if matches!(self.open.last(), None | Some(Open::Subst { .. })) {
            self.word_start = false;
            // Never `case`: the value is a word of its own spelling.
            self.word.push('\0');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ShellPosition;

    fn after(text: &str) -> ShellPosition {
        let mut position = ShellPosition::start();
        position.raw(text);
        position
    }

    /// Each place the lexer reads `'` as opening a quote of the command text.
    #[test]
    fn a_word_is_one_word_in_the_command_text_and_inside_a_substitution() {
        for text in [
            "",
            "echo ",
            "echo --flag=",
            "echo \"a\"'b'$'c'",
            "x=\"$(printf %s ",
            "echo $( (",
            "echo ${v:-x} $((1 + (2))) ",
            "cat <<EOF\nbody $(\nEOF\n",
            "cat <<-'E F'\n\tx\n\tE F\n",
            "cat <<\"EOF\" <<X\na\nEOF\nb\nX\n",
            "# c 'unclosed\n",
            "a#b ",
            "echo \\\\",
            "echo $$",
            "cat <<< ",
        ] {
            assert!(after(text).takes_one_word(), "{text:?}");
        }
    }

    /// The constructs that END before the value: a `$(…)` opened inside
    /// `${…}` is a substitution there, and a closed `$(…)` leaves the text it
    /// was opened in — a `"…"` around it, or the command text, where a later
    /// `case` is followed.
    ///
    /// **Would red if:** a `$` inside `${…}` stopped opening an expansion, or
    /// any character there opened one without its `$` (the nightly mutation
    /// sample's `&&` → `||` survivor in `Lexer::feed`'s brace arm); or a `)`
    /// deepened its `$(…)` instead of closing it (the `-=` → `+=` survivor in
    /// `Lexer::feed_plain`).
    #[test]
    fn a_word_is_one_word_after_the_constructs_before_it_close() {
        for text in [
            "echo ${v:-$(cat ",
            "x=\"$(printf %s a)\" ",
            "echo $(a); case x in x) ",
        ] {
            assert!(after(text).takes_one_word(), "{text:?}");
        }
    }

    /// Each place it does not, and each the lexer cannot follow.
    #[test]
    fn a_word_is_not_one_word_inside_a_quote_comment_heredoc_or_after_an_escape() {
        for text in [
            "echo \"",
            "echo '",
            "echo $'a\\'",
            "echo `",
            "echo \"$(echo `",
            "echo ${v:-",
            "echo $((",
            "echo # ",
            "cat <<EOF\n",
            "cat <<'EOF'\n",
            "cat <<-EOF\nEOF \n",
            "cat <<EOF\n\tEOF\n",
            "cat << ",
            "cat <<",
            "echo \\",
            "echo $",
            "echo \"$(echo \"",
            "echo \"${v:-'",
            "x=$(case a in a) ",
        ] {
            assert!(!after(text).takes_one_word(), "{text:?}");
        }
    }

    /// A heredoc whose delimiter is an expression's value never ends.
    #[test]
    fn a_heredoc_an_expression_delimits_never_ends() {
        let mut position = after("cat <<");
        position.word();
        position.raw("\nx\n\nEOF\n");
        assert!(!position.takes_one_word());
        let mut position = after("cat <<EOF\n");
        position.word();
        position.raw("\n");
        assert!(!position.takes_one_word(), "a body line with a value");
    }
}
