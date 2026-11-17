#!/usr/bin/env python3
r"""Refuse credentials and private data in evidence artifacts and fixtures; sanitize raw artifacts.

Two halves share ONE rule table, so the sanitizer removes exactly what the check refuses:

  check [PATH...]     refuse any file in the scanned set that matches a rule (exit 1)
  sanitize PATH...    rewrite files in place, replacing each matched value with a marker
  --self-test         prove every class against a planted sample, and the sanitizer's
                      idempotence and acceptance by the check

THE SCANNED SET. With no PATH, `check` scans every tracked or untracked-but-not-ignored
file whose repository path matches `SCANNED_GLOBS`: the committed evidence
(`docs/evidence/**`) and the evidence kit that wrote it (`scripts/evidence-kit/**`),
every test input under `test/**`, the `fixtures/` and `goldens/` directories under each
crate's `tests/`, and the `goldens/` under each binary's `tests/`. Those globs are the routing table's `Evidence
and fixtures` row, so `just verify` runs this check for any change to a scanned file.
With PATHs it scans those files, and every file under those directories, whatever their
location. Nothing else is scanned: source code, docs outside `docs/evidence/`, and the
vendored tree are out of scope.

THE REFUSED SET. A file is refused when it is a symbolic link or not UTF-8 (`unscannable`:
a link is never followed, in either scope, because its target is not the committed
content; a binary or compressed artifact can carry anything and cannot be read here), or
when any rule below matches. Each finding names the file, the line, the class and the
rule; it never prints the matched value.

  credential          a PEM private-key block; an OpenAI or Anthropic key (`sk-` and 20+
                      key characters, including `sk-ant-`/`sk-proj-` and Claude session
                      keys); a GitHub token (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36,
                      `github_pat_` + 22); an AWS access key id (`AKIA`/`ASIA` + 16); a
                      Google API key (`AIza` + 35); a Slack token (`xox?-`); a password
                      in a URL's userinfo (`scheme://user:password@`, unless the password
                      is a placeholder); and any assignment (`key = value`, `key: value`,
                      `"key": "value"`) whose key names an api key, secret, password,
                      private, access or signing key, or client secret, and whose value
                      is 12+ characters of `[A-Za-z0-9_-./+=]` holding both a letter and
                      a digit.
  auth_header         an `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `Api-Key`,
                      `Anthropic-Api-Key`, `OpenAI-Api-Key` or `X-Goog-Api-Key` header or
                      key, followed by `:` or `=`, whose value (after an optional
                      `Bearer`/`Basic`/`Token` scheme word) is a SCALAR of 4+ characters.
  bearer_token        `Bearer` followed by 16+ token characters holding a digit; a
                      base64url JSON token (`eyJ` + 20+, optionally dotted: a JWT or a kata
                      API token); an access, refresh, id, oauth, session or auth TOKEN KEY
                      (below) whose value is a SCALAR of 8+ characters; a `code=`,
                      `code_verifier=`, `token=` or `key=` URL query parameter (after `?`
                      or `&`) of 16+ characters of `[A-Za-z0-9._~%-]`.
  cookie              a `Cookie` or `Set-Cookie` header or key whose value holds a
                      `name=value` pair and is not a placeholder; a session cookie by name (`__Secure-*`, `__Host-*`,
                      `sessionKey`, `cf_clearance`, `__cf_bm`, `_cfuvid`, `_puid`,
                      `oai-did`) with a value.
  email               an address `local@domain.tld`, except under a reserved name
                      (RFC 2606/6761: `example.com`, `example.org`, `example.net`, and the
                      `.example`, `.test`, `.invalid`, `.localhost` TLDs), and except a
                      `git@host` that is an SSH remote (followed by `:`, or after
                      `ssh://`), and except a systemd template instance
                      (`user@1000.service`: digits, then a unit suffix).
  private_session     an account, session, conversation, thread, user, org, organization,
                      device or workspace ID KEY (below) whose value is a UUID other than
                      the nil UUID, or 16+ token characters holding a letter and a digit;
                      such a value after kata's own prose for a ChatGPT login,
                      `ChatGPT login for account ` or `logged in to ChatGPT (account `;
                      a home directory `/home/<user>` or `/Users/<user>` whose user is not
                      one of `PLACEHOLDER_USERS`; a host's public IP address. IPv6: a
                      whole run of hex groups and `:` (no letter, digit, `:` or `.` before
                      it, but it may follow an escaped `\n`, `\r` or `\t` or a `key:`
                      letter-and-colon; no letter, digit, `:` or `.digit` after it) that
                      parses as an address in the global unicast block 2000::/3 which
                      `ipaddress` calls global, outside the documentation blocks
                      2001:db8::/32 and 3fff::/20 (named, since `is_global` before Python
                      3.13 admits 3fff::/20). IPv4: a dotted quad (no letter, digit or
                      `.` before it, but it may follow an escaped `\n`, `\r` or `\t`; no
                      letter, digit or `.digit` after it) that parses as an address
                      `ipaddress` calls global and that is not multicast. So loopback
                      (`::1`, 127/8), link-local (fe80::/10, 169.254/16), ULA (fc00::/7),
                      documentation (2001:db8::/32, 3fff::/20, 192.0.2/24, 198.51.100/24,
                      203.0.113/24), private (10/8, 172.16/12, 192.168/16), shared
                      (100.64/10), 6to4, multicast, reserved and the other IANA
                      special-purpose blocks pass, and so do a time (`13:30:37`), a MAC
                      address and a version string (`1.2.3.4.5`, `v9.9.9.9`). An
                      IPv4-mapped IPv6 address is judged by its IPv4.
  provider_payload    a provider-issued identifier in its real format: OpenAI
                      organization (`org-` + 24) and project (`proj_` + 24) ids, Responses
                      object ids (`resp_`/`msg_`/`rs_`/`fc_`/`ws_` + 32+ hex),
                      `chatcmpl-` + 20, `call_` + 20, request ids (`req_` + 32 hex);
                      Anthropic ids (`msg_01`/`toolu_01`/`srvtoolu_01`/`req_01`/
                      `msgbatch_01` + 18); an encrypted reasoning payload (a Fernet token,
                      `gAAAAA` + 40, or an `encrypted_content` value that is a SCALAR of
                      4+); and the account and trace headers `OpenAI-Organization`,
                      `OpenAI-Project`, `Anthropic-Organization-Id`, `X-Request-Id`,
                      `Request-Id`, `OpenAI-Request-Id`, `X-OAI-Request-Id` and `CF-Ray`
                      with a value that is a SCALAR of 4+.

TOKEN KEY and ID KEY. The key's two words (`access` + `token`, `thread` + `id`, …), in any
case, joined by `_`, `-` or nothing: `access_token`, `access-token`, `accessToken`,
`ACCESS_TOKEN`, `thread_id`, `threadId`, `chatgpt-account-id`. They may follow an
IDENTIFIER PREFIX: identifier characters from the identifier's start, ending in `_` or
`-`, or at a camelCase hump (a lowercase letter or digit, then an uppercase letter):
`OPENAI_REFRESH_TOKEN`, `chatgpt_access_token`, `codex_thread_id`, `chatgptAccountId`. The
key must end where the identifier ends, so `max_tokens`, `threadIdx`, `prepaidToken` (no
hump before its `id`) and the all-caps `PREPAIDTOKEN` and `HUMANUSERID` (an all-caps word
has no hump) are not keys. That
is codex app-server's own wire (`threadId`, `sessionId`, `conversationId`) and the
`chatgptAuthTokens` login kata sends (`accessToken`, `chatgptAccountId`).

ESCAPED JSON. Every rule above that names a key (an assignment, field or header) also
matches the key and a double-quoted value escaped inside a JSON string, once or more
(`{\"refresh_token\":\"...\"}`, `\\\"key\\\"`), and a key that follows an escaped newline,
return or tab (`\nauthorization: ...`): that is how a codex or nanocode JSONL transcript
carries tool arguments and `function_call_output` bodies. A bare value, and a
header value running to the end of its line, stops at a backslash, so an escaped `\n` ends
a header line inside a JSON string. The token-shaped rules, the email rule and the home
directory rule match inside escaped JSON as anywhere else, and also right after an
escaped `\n`, `\r` or `\t`, where `\b` sees no word boundary.

A PLACEHOLDER is a value that is empty, starts with the sanitizer's marker `[redacted-`,
is an angle-bracket name (`<token>`), or is a shell or template reference (`$TOKEN`,
`${TOKEN}`, `$(cat f)`, `{{ token }}`). Fixtures spell fake credentials that way. A
SCALAR is one run of `[A-Za-z0-9-._~+/=:%]` that is not a placeholder and not `null`,
`None`, `true` or `false`: a structured value (`{...}`, `[...]`, `Option<String>`) or a
sentence under one of those keys is not a finding, so kata's own `"authorization": {...}`
records pass.

WHAT IT DOES NOT REFUSE, stated so nobody reads more into a pass: it is a pattern check,
never a verifier, and it contacts nothing. A secret in a format none of the rules names
(a password under a key it does not list, a token without the named prefix or shape), a
short or digit-free value under the generic key rules, a multi-word header value
(`Authorization: Digest username="x", ...`), an escaped value that itself holds a
backslash, an email address right after a backslash that is not an escaped `\n`, `\r` or
`\t`, a query parameter other than the four named, an identity in free prose (a name, a
host name, an account id in any sentence but kata's two ChatGPT login forms), an IP
address in a form that does not parse as one (an unbracketed eight-group IPv6 address
with a `:port` after it, a zero-padded IPv4 octet, an integer or hex form), and anything
inside a file outside the scanned set pass. It
cannot tell a revoked or fake token from a live one: a fixture spells a fake one as a
placeholder.

THE SANITIZER replaces each matched VALUE (the header's value, the field's value, the
token itself) with `[redacted-<class>-<n>]`, numbering distinct values per class across
one invocation (the same value gets the same marker, so a transcript keeps its
correlations) and continuing above any marker already in the files. A marker holds no `:`,
`=`, quote or backslash, so it keeps escaped JSON valid, and no rule's key, so no rule
matches a marker (`--self-test` tries every class's marker after every key). A redaction can remove the context an exemption read (the `ssh://`
before `git@host`), so it repeats its pass until one finds nothing, at most `MAX_PASSES`
times: its output has no finding, so the check accepts it and a second run changes
nothing. `--self-test` proves both over the planted corpus and a seeded random mix of
planted samples and controls. It refuses (exit 1, nothing written) a symbolic link, a file
that is not UTF-8, and a file with a finding left after `MAX_PASSES` passes. It is not a
substitute for reading the artifact before committing it.

COST. The scan is meant to be linear in the size of what it reads: a rule whose start could
fall at every position of a long run (a key name's or a URL scheme's characters, a run of
backslashes before a key, a private-key BEGIN line that no END follows) enters the run once,
and the check numbers its findings' lines in one pass (`problem_lines`, the whole of its
per-finding work). `--self-test` measures those input shapes (`_scaling_cases`): sixteen
times the input must cost less than thirty-two times the CPU time, where a quadratic costs
about two hundred and fifty-six. A shape it does not measure is not proven linear.
"""

import argparse
import fnmatch
import gc
import io
import ipaddress
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

# Equal, glob for glob, to the `Evidence and fixtures` row of the routing table, so a
# change to any scanned file routes here (the self-test holds the two equal).
SCANNED_GLOBS = (
    "docs/evidence/**",
    "scripts/evidence-kit/**",
    "test/**",
    "crates/*/tests/fixtures/**",
    "crates/*/tests/goldens/**",
    "bin/*/tests/goldens/**",
)
ROUTING_DOC = "docs/development/verification.md"
ROUTING_ROW = "Evidence and fixtures"

PLACEHOLDER_USERS = frozenset(
    {"alice", "bob", "carol", "op", "user", "runner", "nobody", "kata", "example", "me", "ubuntu"}
)

# The marker holds no `:` or `=` and no rule's key, so no rule matches it.
MARKER = "[redacted-"
MARKER_RE = re.compile(r"\[redacted-([a-z_]+)-(\d+)\]")

CLASSES = (
    "credential",
    "auth_header",
    "bearer_token",
    "cookie",
    "email",
    "private_session",
    "provider_payload",
)

# The value alphabet of a token-shaped value; `[` is outside it, so a marker never matches.
TOKEN_CHARS = r"A-Za-z0-9_\-./+="
# A string escaped once or more inside another JSON string (`\"value\"`, `\\\"value\\\"`):
# how a codex or nanocode JSONL transcript carries tool arguments and outputs.
ESCAPED_DQ = r"\\+\"(?P<edq>[^\"\\\n]*)\\+\""
# One value after `:` or `=`: an escaped, double- or single-quoted string, or a bare run
# that stops at whitespace, a backslash, and the delimiters of JSON, TOML, shell and URL
# query strings.
VALUE = rf"(?:{ESCAPED_DQ}|\"(?P<dq>[^\"\n]*)\"|'(?P<sq>[^'\n]*)'|(?P<bare>[^\s,;&\"'}}\])\\]+))"
# Header and cookie values run to the end of the line, the closing quote, or a backslash
# (an escaped `\n` ends a header line inside a JSON string).
LINE_VALUE = rf"(?:{ESCAPED_DQ}|\"(?P<dq>[^\"\n]*)\"|'(?P<sq>[^'\n]*)'|(?P<bare>[^\n\"'\\]+))"
# Where a token starts: a word boundary, or right after an escaped newline, return or tab
# inside a JSON string (`\nsk-...`), where `\b` sees no boundary.
START = r"(?:(?<=\\[nrt])|\b)"
# A key may itself be quoted, and escaped inside a JSON string (`\"key\"`); it starts at a
# word boundary, or right after an escaped newline, return or tab (`\nauthorization:`). The
# escapes before a quoted key are entered at the first backslash of their run only: a key
# reached from a later backslash is reached from the first one too, the earlier start
# finditer takes, so the same matches come out, and a long backslash run is not rescanned
# from each of its backslashes.
KEY_OPEN = r"(?:(?<=\\[nrt])|(?<!\\)\\*[\"']?\b)"
KEY_CLOSE = r"\\*[\"']?\s*"
# An identifier prefix before a key's words (`codex_thread_id`, `OPENAI_REFRESH_TOKEN`,
# `chatgptAccountId`): from the identifier's first character, any run of identifier
# characters that ends in `_` or `-`, or at a camelCase hump (a lowercase letter or digit,
# then an uppercase letter, matched case-sensitively). So `prepaidToken` is no `idToken`
# (its `id` starts no word), and neither is `PREPAIDTOKEN` (an all-caps word has no hump).
# Starting only where an identifier starts, the prefix never rescans a long kebab-case line
# from each of its hyphens.
KEY_PREFIX = (
    r"(?:(?:(?<=\\[nrt])|(?<![A-Za-z0-9_\-]))[A-Za-z0-9_\-]*?"
    r"(?:[_\-]|(?-i:(?<=[a-z0-9])(?=[A-Z]))))?"
)


def is_placeholder(value):
    v = value.strip()
    if not v or v.startswith(MARKER):
        return True
    if re.fullmatch(r"<[^<>\n]+>", v):
        return True
    if re.match(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{|\()", v):
        return True
    return bool(re.fullmatch(r"\{\{[^{}\n]*\}\}", v))


def _strip_scheme(value):
    return re.sub(r"^(?:bearer|basic|token)\s+", "", value.strip(), flags=re.IGNORECASE)


def _token_like(value, min_len, need_letter=True, need_digit=True):
    if not re.fullmatch(f"[{TOKEN_CHARS}]{{{min_len},}}", value):
        return False
    if need_letter and not re.search(r"[A-Za-z]", value):
        return False
    return not (need_digit and not re.search(r"[0-9]", value))


UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"


# The nil UUID (RFC 9562 §5.9) names no session, account or thread; fixtures use it as one.
NIL_UUID = "00000000-0000-0000-0000-000000000000"


def _id_value(value):
    if value == NIL_UUID:
        return False
    return bool(re.fullmatch(UUID, value)) or _token_like(value, 16)


def _not_placeholder(value):
    return not is_placeholder(value)


# A scalar credential-shaped value: one token, not a JSON literal or a structured value
# (`{`, `[`, `Option<String>`), so kata's own `"authorization": {...}` objects and code
# that names a field are not findings.
SCALAR = r"[A-Za-z0-9\-._~+/=:%]"


def _scalar(value, min_len):
    v = value.strip()
    if is_placeholder(v) or v in ("null", "None", "true", "false"):
        return False
    return bool(re.fullmatch(f"{SCALAR}{{{min_len},}}", v))


def _header_value(value):
    return _scalar(_strip_scheme(value), 4)


def _scalar4(value):
    return _scalar(value, 4)


def _scalar8(value):
    return _scalar(value, 8)


def _cookie_value(value):
    return "=" in value and not is_placeholder(value)


# IPv6's global unicast block: the only one IANA allocates host addresses from. The rest of
# the space is loopback, link-local, ULA, multicast or unassigned.
IPV6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")
# IPv6's documentation blocks, named rather than left to `is_global`: before Python 3.13
# `is_global` counts 3fff::/20 (RFC 9637) as global.
IPV6_DOCUMENTATION = (ipaddress.ip_network("2001:db8::/32"), ipaddress.ip_network("3fff::/20"))


def _public_ipv4(value):
    """A globally reachable unicast IPv4 address: `ipaddress`'s `is_global` (outside every
    IANA special-purpose block: private, loopback, link-local, shared 100.64/10,
    documentation, benchmarking, reserved), and not multicast, which `is_global` admits."""
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def _public_ipv6(value):
    """A globally reachable unicast IPv6 address: in 2000::/3 and `ipaddress`'s `is_global`
    (so not documentation 2001:db8::/32 or 3fff::/20, nor 6to4 or the other IANA
    special-purpose blocks inside 2000::/3)."""
    try:
        addr = ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return (
        addr in IPV6_GLOBAL_UNICAST
        and addr.is_global
        and not any(addr in block for block in IPV6_DOCUMENTATION)
    )


@dataclass(frozen=True)
class Rule:
    cls: str
    name: str
    pattern: re.Pattern
    # Which part of the match is the VALUE the sanitizer replaces: a named group, or the
    # whole match when None (and for the value groups edq/dq/sq/bare, whichever matched).
    group: str | None
    accept: object  # value -> bool: True when the value is a real finding
    # (pattern, text) -> the matches of `pattern.finditer(text)`, found without its
    # rescans; None when `pattern.finditer` is linear itself.
    scan: object = None

    def matches(self, text):
        return self.pattern.finditer(text) if self.scan is None else self.scan(self.pattern, text)


def _kv(cls, name, keys, accept, value=VALUE, sep=r"[:=]", key_open=KEY_OPEN):
    pat = rf"{key_open}(?:{keys})\b{KEY_CLOSE}{sep}\s*{value}"
    return Rule(cls, name, re.compile(pat, re.IGNORECASE), "value", accept)


def _tok(cls, name, pattern, flags=0):
    return Rule(cls, name, re.compile(pattern, flags), None, lambda _v: True)


# A run that a key name or a URL scheme is part of is entered at the run's FIRST point where
# the rule may start (a word boundary, or right after an escaped newline, return or tab),
# never again from a later point of the same run. The name or scheme ends where its run
# ends (the `:` or `=` after it is outside the run), so every start inside one run reaches
# the same end and the same value: the first point finds a match exactly when a later one
# would, and finditer, leftmost first, takes the first. The atomic group keeps a failed run
# from being retried at its later points, so a long run is scanned once, not once per point.
def _run_entry(run, then=""):
    return rf"(?<![{run}])(?>[{run}]*?(?:(?<=\\[nrt])|\b){then})"


SECRET_NAME_RUN = r"A-Za-z0-9_.\-"
URL_SCHEME_RUN = r"A-Za-z0-9+.\-"

PEM_BEGIN = r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
PEM_END = r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
PEM_BEGIN_RE = re.compile(PEM_BEGIN)
PEM_END_RE = re.compile(PEM_END)


def _pem_scan(pattern, text):
    """`pattern.finditer(text)` for the private-key rule (a BEGIN line, then through the
    first END line after it, if one follows): each BEGIN's search for an END stops at the
    first one, which its match then covers, and once a search finds none, no later BEGIN
    searches again. finditer would rescan to the end of the text from every BEGIN that no
    END follows."""
    pos, no_end_from = 0, len(text) + 1
    while (begin := PEM_BEGIN_RE.search(text, pos)) is not None:
        stop = begin.end()
        if stop < no_end_from:
            end = PEM_END_RE.search(text, stop)
            if end is None:
                no_end_from = stop
            else:
                stop = end.end()
        # The rule's own pattern over exactly that span, so the match is the one finditer
        # makes there.
        m = pattern.match(text, begin.start(), stop)
        yield m
        pos = m.end()


RULES = (
    Rule(
        "credential",
        "pem-private-key",
        re.compile(rf"{PEM_BEGIN}(?:.*?{PEM_END})?", re.DOTALL),
        None,
        lambda _v: True,
        _pem_scan,
    ),
    _tok("credential", "openai-anthropic-key", START + r"sk-[A-Za-z0-9_\-]{20,}"),
    _tok("credential", "github-token", START + r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    _tok("credential", "aws-access-key-id", START + r"(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _tok("credential", "google-api-key", START + r"AIza[0-9A-Za-z_\-]{35}"),
    _tok("credential", "slack-token", START + r"xox[abposr]-[A-Za-z0-9\-]{10,}"),
    Rule(
        "credential",
        "url-userinfo-password",
        re.compile(
            _run_entry(URL_SCHEME_RUN, then="(?=[A-Za-z])")
            + rf"[A-Za-z][{URL_SCHEME_RUN}]*://(?P<value>[^\s/:@\"'\\]+:[^\s/@\"'\\]+)@"
        ),
        "value",
        lambda v: not is_placeholder(v.split(":", 1)[1]),
    ),
    _kv(
        "credential",
        "secret-named-assignment",
        rf"[{SECRET_NAME_RUN}]*(?:api[_\-]?key|secret|password|passwd|private[_\-]?key"
        r"|access[_\-]?key|signing[_\-]?key|client[_\-]?secret)",
        lambda v: _token_like(v, 12),
        key_open=_run_entry(SECRET_NAME_RUN),
    ),
    _kv(
        "auth_header",
        "auth-header",
        r"authorization|proxy-authorization|x-api-key|api-key|anthropic-api-key"
        r"|openai-api-key|x-goog-api-key",
        _header_value,
        value=LINE_VALUE,
    ),
    Rule(
        "bearer_token",
        "bearer-scheme",
        re.compile(START + r"bearer\s+(?P<value>[A-Za-z0-9\-._~+/]{16,}=*)", re.IGNORECASE),
        "value",
        lambda v: bool(re.search(r"[0-9]", v)),
    ),
    _tok("bearer_token", "base64url-json-token", START + r"eyJ[A-Za-z0-9_\-]{20,}(?:\.[A-Za-z0-9_\-]*){0,2}"),
    _kv(
        "bearer_token",
        "oauth-token-field",
        KEY_PREFIX + r"(?:access|refresh|id|oauth|session|auth)[_\-]?token",
        _scalar8,
    ),
    Rule(
        "bearer_token",
        "secret-query-parameter",
        re.compile(r"[?&](?:code|code_verifier|token|key)=(?P<value>[A-Za-z0-9._~%\-]{16,})"),
        "value",
        lambda _v: True,
    ),
    _kv("cookie", "cookie-header", r"set-cookie|cookie", _cookie_value, value=LINE_VALUE, sep=":"),
    Rule(
        "cookie",
        "session-cookie",
        re.compile(
            START + r"(?:__Secure-[A-Za-z0-9.\-]+|__Host-[A-Za-z0-9.\-]+|sessionKey|cf_clearance"
            r"|__cf_bm|_cfuvid|_puid|oai-did)=(?P<value>[^;\s\"'\\]+)"
        ),
        "value",
        _not_placeholder,
    ),
    Rule(
        "email",
        "email-address",
        re.compile(
            r"(?:(?<=\\[nrt])|(?<![A-Za-z0-9._%+\-\\]))(?P<value>[A-Za-z0-9._%+\-]+@(?P<domain>(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}))\b"
        ),
        "value",
        None,  # judged with its context by _email_finding
    ),
    _kv(
        "private_session",
        "session-identity-field",
        KEY_PREFIX
        + r"(?:account|session|conversation|thread|user|org|organization|device|workspace)[_\-]?id",
        _id_value,
    ),
    # The ChatGPT account id kata prints in prose, where no ID KEY names it. Refused set:
    # `ChatGPT login for account ` (`kata doctor`'s login row, `kata login status`) or
    # `logged in to ChatGPT (account ` (the end of `kata login openai`), exactly so spelled,
    # then one run of `[A-Za-z0-9_-]` that `_id_value` accepts: a UUID other than the nil
    # UUID, or 16+ characters holding a letter and a digit. Any other sentence naming an
    # account passes.
    Rule(
        "private_session",
        "chatgpt-account-prose",
        re.compile(
            START + r"(?:ChatGPT login for account|logged in to ChatGPT \(account) (?P<value>[A-Za-z0-9_\-]+)"
        ),
        "value",
        _id_value,
    ),
    Rule(
        "private_session",
        "home-directory",
        re.compile(r"(?:(?<=\\[nrt])|(?<![A-Za-z0-9_.\-]))/(?:home|Users)/(?P<value>[A-Za-z0-9._\-]+)"),
        "value",
        lambda v: v not in PLACEHOLDER_USERS,
    ),
    # A host's public address, as an `ss` socket line, a log or a transcript prints it. The
    # candidate is a whole run (nothing address-shaped on either side), so a longer version
    # string or a time (`1.2.3.4.5`, `13:30:37`) is no candidate, and `ipaddress` decides.
    # The IPv6 run leaves out a dotted tail: an IPv4-mapped address's IPv4 is the rule below.
    Rule(
        "private_session",
        "public-ipv6-address",
        re.compile(
            r"(?:(?<=\\[nrt])|(?<=[A-Za-z_]:)|(?<![0-9A-Za-z:.]))"
            r"(?P<value>[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Za-z:]|\.[0-9])"
        ),
        "value",
        _public_ipv6,
    ),
    Rule(
        "private_session",
        "public-ipv4-address",
        re.compile(
            r"(?:(?<=\\[nrt])|(?<![0-9A-Za-z.]))"
            r"(?P<value>[0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9A-Za-z]|\.[0-9])"
        ),
        "value",
        _public_ipv4,
    ),
    _tok("provider_payload", "openai-org-or-project-id", START + r"(?:org-|proj_)[A-Za-z0-9]{24}\b"),
    _tok("provider_payload", "openai-object-id", START + r"(?:resp|msg|rs|fc|ws)_[0-9a-f]{32,}\b"),
    _tok("provider_payload", "openai-completion-or-call-id", START + r"(?:chatcmpl-|call_)[A-Za-z0-9]{20,}\b"),
    _tok("provider_payload", "openai-request-id", START + r"req_[0-9a-f]{32}\b"),
    _tok("provider_payload", "anthropic-id", START + r"(?:msg|toolu|srvtoolu|req|msgbatch)_01[A-Za-z0-9]{18,}\b"),
    _tok("provider_payload", "fernet-encrypted-payload", START + r"gAAAAA[A-Za-z0-9_\-]{40,}={0,2}"),
    _kv("provider_payload", "encrypted-content-field", r"encrypted_content", _scalar4),
    _kv(
        "provider_payload",
        "provider-trace-header",
        r"openai-organization|openai-project|anthropic-organization-id|x-request-id"
        r"|openai-request-id|x-oai-request-id|request-id|cf-ray",
        _scalar4,
        value=LINE_VALUE,
    ),
)

RESERVED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net")
RESERVED_EMAIL_TLDS = ("example", "test", "invalid", "localhost")
# A systemd template instance (`user@1000.service`) has an address's shape and is not one.
SYSTEMD_INSTANCE = re.compile(r"[0-9]+\.(?:service|slice|scope|socket|target|mount|timer)")


def _email_finding(text, m):
    domain = m.group("domain").lower()
    if domain in RESERVED_EMAIL_DOMAINS or any(domain.endswith("." + d) for d in RESERVED_EMAIL_DOMAINS):
        return False
    if domain.rsplit(".", 1)[-1] in RESERVED_EMAIL_TLDS:
        return False
    if SYSTEMD_INSTANCE.fullmatch(domain):
        return False
    local = m.group("value").split("@", 1)[0]
    if local == "git":
        after = text[m.end() : m.end() + 1]
        before = text[max(0, m.start() - 6) : m.start()]
        if after == ":" or before == "ssh://":
            return False
    return True


@dataclass(frozen=True)
class Finding:
    cls: str
    rule: str
    start: int  # span of the value the sanitizer replaces
    end: int


def _value_span(rule, m):
    if rule.group is None:
        return m.start(), m.end()
    if rule.group == "value" and "value" in m.re.groupindex:
        return m.span("value")
    for g in ("edq", "dq", "sq", "bare"):
        if m.group(g) is not None:
            return m.span(g)
    raise AssertionError(f"rule {rule.name} matched without a value group")


def findings(text):
    """Every finding in `text`, overlaps resolved: earliest start, then longest span."""
    raw = []
    for rule in RULES:
        for m in rule.matches(text):
            start, end = _value_span(rule, m)
            value = text[start:end]
            if rule.cls == "email":
                if not _email_finding(text, m):
                    continue
            elif not rule.accept(value):
                continue
            raw.append(Finding(rule.cls, rule.name, start, end))
    raw.sort(key=lambda f: (f.start, -(f.end - f.start)))
    kept = []
    for f in raw:
        if kept and f.start < kept[-1].end:
            continue
        kept.append(f)
    return kept


def line_numbers(text, offsets):
    """The 1-based line of each offset in `offsets`, which ascend: one pass over `text`, not
    one count from its start per offset."""
    lines, line, prev = [], 1, 0
    for offset in offsets:
        line += text.count("\n", prev, offset)
        prev = offset
        lines.append(line)
    return lines


def read_text(path):
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _repo_root():
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    )
    return out.stdout.strip()


def default_scope(root):
    out = subprocess.run(
        ["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        check=True,
    )
    paths = sorted({p for p in out.stdout.decode().split("\0") if p})
    return [
        p
        for p in paths
        if in_scope(p) and (os.path.islink(os.path.join(root, p)) or os.path.isfile(os.path.join(root, p)))
    ]


def in_scope(rel):
    return any(fnmatch.fnmatch(rel, g) for g in SCANNED_GLOBS)


def expand(paths):
    """The files under `paths`. A symbolic link is returned as itself, never followed, so the
    check and the sanitizer refuse it rather than read the file it names."""
    files = []
    for p in paths:
        if os.path.islink(p):
            files.append(p)
        elif os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames.sort()
                files.extend(os.path.join(dirpath, d) for d in dirnames if os.path.islink(os.path.join(dirpath, d)))
                files.extend(os.path.join(dirpath, f) for f in sorted(filenames))
        elif os.path.isfile(p):
            files.append(p)
        else:
            raise FileNotFoundError(p)
    return files


def check_files(files, display=lambda p: p):
    """Return the refusal lines for `files` (empty when every file is clean)."""
    problems = []
    for path in files:
        if os.path.islink(path):
            problems.append(f"  {display(path)}: unscannable: a symbolic link")
            continue
        text = read_text(path)
        if text is None:
            problems.append(f"  {display(path)}: unscannable: not UTF-8")
            continue
        problems.extend(problem_lines(display(path), text, findings(text)))
    return problems


def problem_lines(name, text, found):
    """The refusal line of each of `text`'s findings `found` (ascending), each naming its
    line: the check's whole per-finding cost, which `--self-test` times."""
    return [
        f"  {name}:{line}: {f.cls} ({f.rule})"
        for f, line in zip(found, line_numbers(text, [f.start for f in found]))
    ]


def cmd_check(args):
    if args.paths:
        files = expand(args.paths)
        display = lambda p: p  # noqa: E731
    else:
        root = _repo_root()
        rel = default_scope(root)
        files = [os.path.join(root, p) for p in rel]
        display = lambda p: os.path.relpath(p, root)  # noqa: E731
    problems = check_files(files, display)
    if problems:
        print(
            f"evidence-sanitize: REFUSED — {len(problems)} finding(s) in {len(files)} file(s) "
            "(values not printed; run `scripts/evidence-sanitize.py sanitize` on a raw "
            "artifact, or spell a fixture's fake credential as a placeholder):",
            file=sys.stderr,
        )
        for line in problems:
            print(line, file=sys.stderr)
        return 1
    print(f"evidence-sanitize: ok — {len(files)} file(s) scanned, no finding")
    return 0


class Numbering:
    """Distinct values per class get distinct markers; numbering continues above any marker
    already present, so a partly sanitized file never reuses a number."""

    def __init__(self, texts):
        self.next = dict.fromkeys(CLASSES, 1)
        for text in texts:
            for m in MARKER_RE.finditer(text):
                cls, n = m.group(1), int(m.group(2))
                if cls in self.next:
                    self.next[cls] = max(self.next[cls], n + 1)
        self.seen = {}

    def marker(self, cls, value):
        key = (cls, value)
        if key not in self.seen:
            self.seen[key] = self.next[cls]
            self.next[cls] += 1
        return f"[redacted-{cls}-{self.seen[key]}]"


# A redaction can remove the context an exemption read (`ssh://` before `git@host`), so a
# pass can expose a finding the previous pass did not have; the sanitizer repeats until a
# pass finds nothing, and its output is a fixed point by construction.
MAX_PASSES = 4


def _sanitize_pass(text, numbering, counts):
    out = []
    pos = 0
    for f in findings(text):
        out.append(text[pos : f.start])
        out.append(numbering.marker(f.cls, text[f.start : f.end]))
        pos = f.end
        counts[f.cls] = counts.get(f.cls, 0) + 1
    out.append(text[pos:])
    return "".join(out)


def sanitize_text(text, numbering):
    """Return (sanitized text, {class: values redacted}), or (None, counts) when MAX_PASSES
    passes still leave a finding."""
    counts = {}
    for _ in range(MAX_PASSES):
        if not findings(text):
            return text, counts
        text = _sanitize_pass(text, numbering, counts)
    return (text if not findings(text) else None), counts


def cmd_sanitize(args, out=sys.stdout):
    files = expand(args.paths)
    texts = {}
    bad = []
    for path in files:
        text = None if os.path.islink(path) else read_text(path)
        if text is None:
            bad.append(path)
        else:
            texts[path] = text
    if bad:
        print(
            "evidence-sanitize: REFUSED — a symbolic link or not UTF-8, cannot sanitize (nothing written):",
            file=out,
        )
        for p in bad:
            print(f"  {p}", file=out)
        return 1
    numbering = Numbering(texts.values())
    results = {path: sanitize_text(text, numbering) for path, text in texts.items()}
    stuck = [path for path, (new, _c) in results.items() if new is None]
    if stuck:
        print(
            f"evidence-sanitize: REFUSED — a finding survives {MAX_PASSES} passes (nothing written):",
            file=out,
        )
        for p in stuck:
            print(f"  {p}", file=out)
        return 1
    total = 0
    for path, text in texts.items():
        new, counts = results[path]
        if new != text:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(new)
            summary = ", ".join(f"{c} {n}" for c, n in sorted(counts.items()))
            print(f"  {path}: {summary}", file=out)
            total += sum(counts.values())
    print(f"evidence-sanitize: {total} value(s) redacted in {len(files)} file(s)", file=out)
    return 0


# ── self-test ────────────────────────────────────────────────────────────────
# Each planted value is ASSEMBLED at run time (`_j`), so this file holds no literal
# credential for any scanner, and the check's own scope never includes scripts/.


FUZZ_CASES = 2000


def _j(*parts):
    return "".join(parts)


def _planted():
    hexs = "0123456789abcdef" * 4
    alnum = "aB3dE5gH7jK9mN1pQ3rS5tU7vW9xY1z" * 2
    return [
        ("credential", "pem-private-key", _j("-----BEGIN ", "OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----\n")),
        ("credential", "openai-anthropic-key", _j("OPENAI=", "sk-", "proj-", alnum[:40], "\n")),
        ("credential", "openai-anthropic-key", _j("key: ", "sk-", "ant-", "sid01-", alnum[:30], "\n")),
        ("credential", "github-token", _j("token ", "gh", "p_", alnum[:36], "\n")),
        ("credential", "github-token", _j("GH_TOKEN=", "github_", "pat_", alnum[:40], "\n")),
        ("credential", "aws-access-key-id", _j("id ", "AKIA", "QWERTYUIOP234567", "\n")),
        ("credential", "google-api-key", _j("k=", "AIza", alnum[:35], "\n")),
        ("credential", "slack-token", _j("t ", "xox", "b-", "123456789012-abcdef", "\n")),
        ("credential", "secret-named-assignment", _j('{"client_secret": "', "s3cr3tV4lu3XYZ", '"}\n')),
        ("credential", "secret-named-assignment", _j("KATA_API_SIGNING_KEY=", hexs, "\n")),
        ("credential", "url-userinfo-password", _j("remote https://user:", "p4ssw0rdSecret", "@github.com/x.git\n")),
        ("auth_header", "auth-header", _j("> Authorization: ", "Basic ", "dXNlcjpwYXNz", "\n")),
        ("auth_header", "auth-header", _j("x-api-key: ", "plainkeyvalue", "\n")),
        ("auth_header", "auth-header", _j('{"authorization": "', "Token ", "abc123def", '"}\n')),
        ("bearer_token", "bearer-scheme", _j("sent bearer ", "abcDEF0123456789xyz", "\n")),
        ("bearer_token", "base64url-json-token", _j("tok=", "eyJ", "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", ".", "eyJ", "zdWIiOiIxMjM0In0", ".sig\n")),
        ("bearer_token", "base64url-json-token", _j("token: ", "eyJ", "zY29wZSI6Im9wZXJhdGUiLCJpc3N1ZWRfZm9yIjoiZTEifQ", "\n")),
        ("bearer_token", "oauth-token-field", _j('{"refresh_token": "', "rt.Zx81", 'abc"}\n')),
        ("bearer_token", "secret-query-parameter", _j("GET /auth/callback?", "code=", "ac_9f8e7d6c5b4a3210", "&state=x\n")),
        ("bearer_token", "secret-query-parameter", _j("fetch https://h.example.net/x?", "token=", "abcdef1234567890abcd", "\n")),
        ("cookie", "cookie-header", _j("Cookie: ", "theme=dark; uid=42", "\n")),
        ("cookie", "cookie-header", _j("< set-cookie: ", "a=b; Path=/", "\n")),
        ("cookie", "session-cookie", _j("jar ", "cf_clearance", "=", "Xyz.123", "\n")),
        ("email", "email-address", _j("Author: Jane <", "jane.doe", "@", "gmail.com", ">\n")),
        ("email", "email-address", _j("by ", "12345+someone", "@", "users.noreply.github.com", "\n")),
        ("private_session", "session-identity-field", _j('{"chatgpt_account_id": "', "1b2c3d4e-0000-4abc-8def-1234567890ab", '"}\n')),
        ("private_session", "session-identity-field", _j("session-id = ", "sess9f8e7d6c5b4a3", "\n")),
        ("private_session", "home-directory", _j("cwd ", "/home/", "janedoe", "/work/repo\n")),
        ("private_session", "home-directory", _j("at ", "/Users/", "jd", "/src\n")),
        ("provider_payload", "openai-org-or-project-id", _j("org ", "org-", alnum[:24], "\n")),
        ("provider_payload", "openai-object-id", _j('"id": "', "resp_", hexs[:48], '"\n')),
        ("provider_payload", "openai-completion-or-call-id", _j("id ", "call_", alnum[:24], "\n")),
        ("provider_payload", "openai-request-id", _j("rid ", "req_", hexs[2:34], "\n")),
        ("provider_payload", "anthropic-id", _j('"id": "', "msg_01", alnum[:22], '"\n')),
        ("provider_payload", "fernet-encrypted-payload", _j("blob ", "gAAAAA", alnum[:60], "\n")),
        ("provider_payload", "encrypted-content-field", _j('{"encrypted_content": "', "AAAAopaqueBlob", '"}\n')),
        ("provider_payload", "provider-trace-header", _j("openai-organization: ", "acme-corp", "\n")),
        ("provider_payload", "provider-trace-header", _j("cf-ray: ", "8f0e1d2c3b4a-IAD", "\n")),
        # The same key-value rules over JSON escaped inside a JSON string, as a JSONL
        # transcript carries a tool's arguments and output (one sample per key-value rule).
        ("credential", "secret-named-assignment", _j('{"arguments":"{\\"password\\":\\"', "hunter2hunter2X9", '\\"}"}\n')),
        ("auth_header", "auth-header", _j('{"arguments":"{\\"authorization\\":\\"Basic ', "dXNlcjpwYXNzd29yZA==", '\\"}"}\n')),
        ("auth_header", "auth-header", _j('{"output":"GET / HTTP/1.1\\nauthorization: Basic ', "dXNlcjpwYXNz", '\\nhost: h\\n"}\n')),
        ("bearer_token", "oauth-token-field", _j('{"output":"{\\"tokens\\":{\\"refresh_token\\":\\"', "rt_AbCdEf12xyz", '\\"}}"}\n')),
        ("cookie", "cookie-header", _j('{"arguments":"{\\"cookie\\":\\"', "sid=abc123", '\\"}"}\n')),
        ("private_session", "session-identity-field", _j('{"output":"{\\\\\\"account_id\\\\\\":\\\\\\"', "1b2c3d4e-0000-4abc-8def-1234567890ab", '\\\\\\"}"}\n')),
        ("provider_payload", "encrypted-content-field", _j('{"output":"{\\"encrypted_content\\":\\"', "AAAAopaqueBlobxx", '\\"}"}\n')),
        ("provider_payload", "provider-trace-header", _j('{"output":"{\\"x-request-id\\": \\"', "abc-123-def", '\\"}"}\n')),
        # camelCase keys (codex app-server's own wire, and the chatgptAuthTokens login kata
        # sends) and keys behind an identifier prefix.
        ("private_session", "session-identity-field", _j('{"threadId": "', "2c3d4e5f-1111-4abc-8def-1234567890ab", '"}\n')),
        ("private_session", "session-identity-field", _j('{"sessionId": "', "3d4e5f60-2222-4abc-8def-1234567890ab", '"}\n')),
        ("private_session", "session-identity-field", _j('{"conversationId": "', "4e5f6071-3333-4abc-8def-1234567890ab", '"}\n')),
        ("private_session", "session-identity-field", _j('{"chatgptAccountId": "', "5f607182-4444-4abc-8def-1234567890ab", '"}\n')),
        ("private_session", "session-identity-field", _j('{"codex_thread_id": "', "60718293-5555-4abc-8def-1234567890ab", '"}\n')),
        ("bearer_token", "oauth-token-field", _j('{"accessToken": "', "opaqueTok", "12345678abc", '"}\n')),
        ("bearer_token", "oauth-token-field", _j('{"refreshToken": "', "opaqueRef", "87654321xyz", '"}\n')),
        ("bearer_token", "oauth-token-field", _j("OPENAI_REFRESH_TOKEN=", "rtAbCdEf12", "xyz9999", "\n")),
        ("bearer_token", "oauth-token-field", _j('{"chatgpt_access_token": "', "opaqueAcc", "13572468def", '"}\n')),
        # The identity a validation round's raw artifacts carry: `kata doctor`'s
        # commit_identity row, and a setup log's round, data directory and search paths.
        ("email", "email-address", _j("[pass] commit_identity              kata would commit as `Jane Doe <",
                                      "jane.doe", "@", "fastmail.online", ">` in this repository\n")),
        ("private_session", "home-directory", _j("prelude: round ", "/home/", "janedoe", "/kata-evidence/val, harness codex-stock\n")),
        ("private_session", "home-directory", _j("  node.data_dir = ", "/home/", "janedoe", "/ke/e1p-codex-stock/.kata/data\n")),
        ("private_session", "home-directory", _j("    [missing] ", "/home/", "janedoe", "/.kata/workflows\n")),
        # The ChatGPT account id kata prints in prose: `kata doctor`'s login row, `kata login
        # status [--check]`'s, and the line `kata login openai` ends with.
        ("private_session", "chatgpt-account-prose", _j("[pass] agents.default            openai-chatgpt.json: ChatGPT login for account ",
                                                        "7a8b9c0d-7777-4abc-8def-1234567890ab", ", refresh token stored\n")),
        ("private_session", "chatgpt-account-prose", _j("  openai-chatgpt.json: ChatGPT login for account ",
                                                        "8b9c0d1e-8888-4abc-8def-1234567890ab",
                                                        "; access token expires 2026-11-09T12:00:00+00:00; refresh token stored; revision 3\n")),
        ("private_session", "chatgpt-account-prose", _j("kata is logged in to ChatGPT (account ",
                                                        "9c0d1e2f-9999-4abc-8def-1234567890ab", "); its login is /home/kata/x.json\n")),
        # A host's public address: E3's `ss -tinpH` socket line (the worker's source and
        # its peer), a full and an escaped form, and IPv4 bare, at a sentence's end and
        # inside an IPv4-mapped IPv6 address.
        ("private_session", "public-ipv6-address", _j('0      0       [', "2606:4700:4700::1111",
                                                      ']:55120 [::1]:443   users:(("kata-worker",pid=7,fd=30))\n')),
        ("private_session", "public-ipv6-address", _j("src ", "2a00:1450:4001:82a:0:0:0:200e", " dev eth0\n")),
        ("private_session", "public-ipv6-address", _j('{"output":"peer\\n', "2a00:1450:4001:82a::200e", '\\n"}\n')),
        ("private_session", "public-ipv6-address", _j("the egress address was ", "2606:4700:4700::1111", ".\n")),
        ("private_session", "public-ipv6-address", _j("src:", "2606:4700:4700::1001", " dev eth0\n")),
        ("private_session", "public-ipv4-address", _j("ESTAB 0 0 ", "8.8.8.8", ":443 users:((\"curl\"))\n")),
        ("private_session", "public-ipv4-address", _j("the egress address was ", "1.1.1.1", ".\n")),
        ("private_session", "public-ipv4-address", _j("[::ffff:", "8.8.4.4", "]:443\n")),
    ]


# Text that resembles a finding and must PASS: each line names why it is accepted.
CLEAN_CONTROLS = """\
Authorization: Bearer $TOKEN
curl -H "authorization: Bearer ${TOKEN}" http://127.0.0.1:8400/api/v1/executions
Authorization: <token>
x-api-key: [redacted-auth_header-3]
"access_token": "<access-token>"
"refresh_token": "{{ refresh }}"
api_key = "short"
password = "no-digits-here-at-all"
max_tokens = 4096
input_tokens: 12509
a bearer token is required
Bearer authentication-without-a-digit-anywhere
kata commits as Grace Hopper <grace@example.test>
mail ops@example.com and a@b.example.org
git@github.com:owner/repo.git
ssh://git@github.com/owner/repo.git
serde@1.0.219 and @types/node
/home/alice/work and /Users/op/src and /home/user and $HOME/x
cookie: <cookie>
session_id = "sess-1"
thread_id: 7
sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
exec-01JD7Q8Z3K4M5N6P7Q8R9S0T1V and resp_123 and msg_abc and req_short
encrypted_content: <opaque>
"encrypted_content": null, "authorization": {"decision": "allow"}, "cookie": {"jar": 1}
Authorization: the operator's decision, recorded
access_token: Option<String>, x-request-id: null
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice and /home/ubuntu/kata
request-id: $REQUEST_ID
cf_clearance=$CF_CLEARANCE and __Secure-next-auth.session-token=<session-token>
git clone https://x-access-token:${GH_TOKEN}@github.com/o/r.git and https://user:<password>@h.example/x
http://127.0.0.1:8400/api/v1/executions?key=short&token=$TOKEN
{"arguments":"{\\"access_token\\":\\"<access-token>\\",\\"session_id\\":\\"sess-1\\",\\"password\\":\\"short\\"}"}
{"threadId": "<thread-id>", "accessToken": "$TOKEN", "conversationId": null, "maxTokens": 4096}
"sessionId": "00000000-0000-0000-0000-000000000000"
ChatGPT login for account 00000000-0000-0000-0000-000000000000, ChatGPT login for account <account>
ChatGPT login for account acct-owner; logged in to ChatGPT (account $ACCOUNT); a login for account 7a8b9c0d-6666-4abc-8def-1234567890ab
prepaidToken: abcdef12345678 and paidtoken = 12345678 and threadIdx: 7a8b9c0d-6666-4abc-8def-1234567890ab
PREPAIDTOKEN=abcdefgh12345 and PAIDTOKEN: abcdefgh12345 and GUIDTOKEN=abcdefgh12345 and HUMANUSERID=abcdefgh1234567890ab
::1 and 127.0.0.1 and [::1]:8400 and 0.0.0.0:0 and [::]:0 and 255.255.255.255 and ::ffff:127.0.0.1
fe80::1%eth0 and fe80::a00:27ff:fe4e:66a1 and fd00::1 and fd12:3456:789a::1 and fc00::1
2001:db8::1 and [2001:db8:85a3::8a2e:370:7334]:443 and 3fff::1 and 3fff:fff:1::2
192.0.2.1 and 198.51.100.7 and 203.0.113.9 and 10.0.0.1 and 172.16.5.4 and 192.168.1.1 and ::ffff:10.0.0.1
100.64.0.1 and 169.254.1.1 and 224.0.0.251 and 240.0.0.1 and ff02::1 and 2002::/16
at 13:30:37, 2026-11-09T12:00:00+00:00, aa:bb:cc:dd:ee:ff, std::fs::read, dead::beef, 1.0.219 and 1.2.3.4.5 and v9.9.9.9
"""


# The scan is linear in its input. Each case below is an input shape on which a rule can
# rescan the rest of a run from each of its positions, or the check count each finding's
# line from the file's start: the case made SCALING_FACTOR times longer must cost less than
# SCALING_LIMIT times the CPU time (a quadratic costs about SCALING_FACTOR squared). This
# process's CPU time, not wall time, the least of SCALING_REPEATS interleaved runs per size,
# so a loaded host slows both sizes alike instead of failing the ratio.
SCALING_FACTOR = 16
SCALING_LIMIT = 32
SCALING_REPEATS = 5


def _scaling_cases():
    """(label, base size in characters, input of n characters, the scan to time)."""
    pem = _j("-----BEGIN ", "RSA PRIVATE KEY-----\n")
    # Its rescans are a small share of every rule's scan, so this case times its rule alone.
    pem_rule = next(r for r in RULES if r.name == "pem-private-key")

    # The findings are given, so this case times the check's numbering, not the rules.
    def lines(n):
        text = ("x" * 7 + "\n") * (n // 8)
        return text, [Finding("home-directory", "home-directory", i, i + 1) for i in range(0, len(text), 8)]

    return (
        ("a dotted run (a.a.a...)", 2048, lambda n: "a." * (n // 2), findings),
        ("a hyphenated run (a-a-a...)", 2048, lambda n: "a-" * (n // 2), findings),
        ("a backslash run", 2048, lambda n: "\\" * n, findings),
        ("a colon run (2a:2a:2a...)", 2048, lambda n: "2a:" * (n // 3), findings),
        ("a dotted digit run (8.8.8...)", 2048, lambda n: "8." * (n // 2), findings),
        ("private-key headers with no end line", 4096, lambda n: pem * (n // len(pem)),
         lambda t: list(pem_rule.matches(t))),
        ("a finding on every line, numbered", 16384, lines, lambda t: problem_lines("f", *t)),
    )


def _cpu_seconds(scan, case_input):
    start = time.process_time()
    scan(case_input)
    return time.process_time() - start


def _scaling_failures():
    failures = []
    gc.disable()
    try:
        for label, base, make, scan in _scaling_cases():
            small_input, large_input = make(base), make(base * SCALING_FACTOR)
            small = large = float("inf")
            for _ in range(SCALING_REPEATS):
                small = min(small, _cpu_seconds(scan, small_input))
                large = min(large, _cpu_seconds(scan, large_input))
            if large >= SCALING_LIMIT * small:
                failures.append(
                    f"the scan is not linear on {label}: {SCALING_FACTOR}x the input cost "
                    f"{large / small:.0f}x the CPU time (limit {SCALING_LIMIT}x)"
                )
    finally:
        gc.enable()
    return failures


def _routing_row_globs():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", ROUTING_DOC), encoding="utf-8") as fh:
        text = fh.read()
    body = text.split("<!-- routing:begin -->", 1)[1].split("<!-- routing:end -->", 1)[0]
    for line in body.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and cells[0] == ROUTING_ROW:
            return [g.strip().strip("`") for g in cells[1].split(",") if g.strip()]
    return None


def _rule_classes():
    return {r.name: r.cls for r in RULES}


def _sanitized(text, failures, label):
    """sanitize_text's output, or `text` with a failure recorded when it does not converge."""
    out, counts = sanitize_text(text, Numbering([text]))
    if out is None:
        failures.append(f"the sanitizer does not converge on {label}")
        return text, counts
    return out, counts


def self_test():
    failures = []
    planted = _planted()
    names = _rule_classes()

    # 1. Every rule has a planted sample, and every sample is refused by exactly its
    #    rule's class. A rule nobody plants proves nothing.
    planted_rules = {rule for _c, rule, _t in planted}
    for rule in names:
        if rule not in planted_rules:
            failures.append(f"rule {rule} has no planted sample")
    for cls, rule, text in planted:
        got = findings(text)
        if [(f.cls, f.rule) for f in got] != [(cls, rule)]:
            failures.append(f"planted {cls}/{rule}: found {[(f.cls, f.rule) for f in got]}")
    for cls in CLASSES:
        if not any(c == cls for c, _r, _t in planted):
            failures.append(f"class {cls} has no planted sample")

    # 2. The controls pass: a check that refuses placeholders or reserved names is wider
    #    than the set it states.
    for f in findings(CLEAN_CONTROLS):
        failures.append(
            f"clean control refused at line {line_numbers(CLEAN_CONTROLS, [f.start])[0]}: {f.cls} ({f.rule})"
        )

    corpus = "".join(t for _c, _r, t in planted) + CLEAN_CONTROLS
    quiet = io.StringIO()
    with tempfile.TemporaryDirectory(prefix="evidence-sanitize-") as tmp:
        raw = os.path.join(tmp, "raw.txt")
        with open(raw, "w", encoding="utf-8") as fh:
            fh.write(corpus)

        # 3. The check refuses the raw corpus through the file path, and never prints a value.
        #    A refusal line is `  <path>:<line>: <class> (<rule>)`: the path is the caller's
        #    (the random temp directory can spell a short planted value, such as `jd`), so
        #    the value is looked for in everything the check writes AFTER it.
        problems = check_files([raw])
        if len(problems) != len(planted):
            failures.append(f"check over the raw corpus: {len(problems)} findings, want {len(planted)}")
        prefix = f"  {raw}:"
        written = []
        for p in problems:
            if p.startswith(prefix):
                written.append(p[len(prefix) :])
            else:
                failures.append(f"check output line does not lead with the scanned path: {p!r}")
        for _c, _r, text in planted:
            for f in findings(text):
                value = text[f.start : f.end]
                if any(value in w for w in written):
                    failures.append(f"check output prints the value of {f.rule}")

        # 4. The sanitizer's output is accepted by the check, leaves the controls byte-for-byte,
        #    and is a fixed point (a second run changes nothing).
        once, _ = _sanitized(corpus, failures, "the corpus")
        if findings(once):
            failures.append(f"sanitized corpus still has findings: {[(f.cls, f.rule) for f in findings(once)]}")
        if not once.endswith(CLEAN_CONTROLS):
            failures.append("the sanitizer changed a clean control")
        twice, counts = _sanitized(once, failures, "its own output")
        if twice != once or counts:
            failures.append("the sanitizer is not idempotent")
        for _c, _r, text in planted:
            for f in findings(text):
                if text[f.start : f.end] in once:
                    failures.append(f"sanitized corpus still holds the value of {f.rule}")

        # 5. The CLI round trip on a file: sanitize in place, then check accepts it, then a
        #    second sanitize leaves the bytes unchanged.
        if cmd_sanitize(argparse.Namespace(paths=[raw]), out=quiet) != 0:
            failures.append("sanitize CLI failed")
        with open(raw, encoding="utf-8") as fh:
            first = fh.read()
        if check_files([raw]):
            failures.append("check refuses the sanitize CLI's output")
        cmd_sanitize(argparse.Namespace(paths=[raw]), out=quiet)
        with open(raw, encoding="utf-8") as fh:
            if fh.read() != first:
                failures.append("sanitize CLI is not idempotent on a file")

        # 6. The same value gets the same marker; numbering continues above existing markers.
        same = "Cookie: a=1\nCookie: a=1\nCookie: b=2\n"
        out, _ = sanitize_text(same, Numbering([same]))
        if out != "Cookie: [redacted-cookie-1]\nCookie: [redacted-cookie-1]\nCookie: [redacted-cookie-2]\n":
            failures.append(f"marker numbering: {out!r}")
        partial = "Cookie: [redacted-cookie-4]\nCookie: c=3\n"
        out, _ = sanitize_text(partial, Numbering([partial]))
        if "Cookie: [redacted-cookie-5]" not in out:
            failures.append(f"numbering does not continue above an existing marker: {out!r}")

        # 7. A session cookie with attributes after it keeps them, in ONE pass, and the
        #    marker it leaves is no cookie header (a marker once read as `cookie:` + value).
        for raw_line, want in (
            (_j("set by server: cf_clearance=", "Xyz.123", "; path=/; domain=.example.com\n"),
             "set by server: cf_clearance=[redacted-cookie-1]; path=/; domain=.example.com\n"),
            (_j("_cfuvid=", "abc.def-123", "; HttpOnly; SameSite=None\n"),
             "_cfuvid=[redacted-cookie-1]; HttpOnly; SameSite=None\n"),
        ):
            got = _sanitize_pass(raw_line, Numbering([raw_line]), {})
            if got != want or findings(got):
                failures.append(f"cookie round trip: {got!r}, findings {[(f.cls, f.rule) for f in findings(got)]}")

        # 8. No rule matches a marker of any class, after any key that rule reads.
        for cls in CLASSES:
            for key in ("cookie", "set-cookie", "authorization", "x-api-key", "password", "access_token",
                        "session_id", "encrypted_content", "x-request-id", "cf_clearance", "bearer"):
                for sep in (": ", "=", '": "', '\\":\\"'):
                    text = f"{key}{sep}[redacted-{cls}-1]; a=b [redacted-{cls}-2]\n"
                    if findings(text):
                        failures.append(f"a marker is a finding: {text!r} -> {[(f.cls, f.rule) for f in findings(text)]}")

        # 9. A codex-shaped JSONL line, with credentials in JSON escaped inside its output
        #    string, sanitizes to valid JSON whose inner JSON is valid and holds no value.
        rt, acct = _j("rt_", "AbCdEf12", "xyzXYZ34"), "1b2c3d4e-0000-4abc-8def-1234567890ab"
        jar = _j("cf_clearance=", "Xyz.123")
        inner = json.dumps({"tokens": {"refresh_token": rt, "account_id": acct}, "jar": jar})
        line = json.dumps({"type": "function_call_output", "output": inner}) + "\n"
        got, _ = _sanitized(line, failures, "a JSONL line")
        try:
            decoded = json.loads(json.loads(got)["output"])
        except (ValueError, KeyError, TypeError) as err:
            failures.append(f"sanitized JSONL is not valid nested JSON: {err}: {got!r}")
        else:
            tokens = decoded["tokens"].values()
            if (
                rt in got
                or acct in got
                or not all(v.startswith(MARKER) for v in tokens)
                or decoded["jar"] != "cf_clearance=[redacted-cookie-1]"
            ):
                failures.append(f"sanitized JSONL still holds a value: {got!r}")
        # Each token-shaped value right after an escaped newline or tab is found, and its
        # redaction keeps the escape (`\n[redacted-…]`, never `\[redacted-…]`).
        after_escape = [
            _j("sk-", "proj-", "aB3dE5gH7jK9mN1pQ3rS5tU7vW9"),
            _j("jane", "@", "gmail.com"),
            _j("/home/", "janedoe/x"),
            _j("_cfuvid=", "abc.def-123; Path=/"),
            _j("Bearer ", "abcDEF0123456789xyz"),
            _j("call_", "aB3dE5gH7jK9mN1pQ3rS5tU7"),
        ]
        line = json.dumps({"output": "\n".join(["out:", *after_escape]) + "\t" + _j("eyJ", "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")})
        got, _ = _sanitized(line, failures, "escaped newlines")
        if len(findings(line)) != len(after_escape) + 1:
            failures.append(f"after an escaped newline: {[(f.cls, f.rule) for f in findings(line)]}")
        try:
            json.loads(got)
        except ValueError as err:
            failures.append(f"a redaction after an escaped newline breaks the JSON: {err}: {got!r}")

        # 10. A seeded random mix of planted samples, controls and separators, run together
        #     without newlines: the sanitizer's output has no finding and is a fixed point.
        rng = random.Random(1)
        pieces = [t.rstrip("\n") for _c, _r, t in planted] + CLEAN_CONTROLS.splitlines()
        pieces += [" ", '"', "'", "=", ": ", ";", "&", "?", "@", "/home/", "Bearer ", "Cookie: ", "\\\""]
        for _ in range(FUZZ_CASES):
            text = "".join(rng.choice(pieces) for _ in range(rng.randint(2, 6)))
            once, _ = sanitize_text(text, Numbering([text]))
            again, counts = sanitize_text(once, Numbering([once])) if once is not None else (None, {})
            if once is None or findings(once) or again != once or counts:
                failures.append(f"random mix not sanitized to a fixed point: {text!r} -> {once!r} -> {again!r}")
                break

        # 11. A redaction that removes an exemption's context needs a second pass (`call_…ssh`
        #     swallows the `ssh://` that exempted `git@host`); with one pass allowed, the
        #     sanitizer refuses the file and writes nothing.
        ctx = os.path.join(tmp, "ctx.txt")
        ctx_text = _j("id call_", "aB3dE5gH7jK9mN1pQ3rS5tU7", "ssh://git@github.com/o/r\n")
        with open(ctx, "w", encoding="utf-8") as fh:
            fh.write(ctx_text)
        global MAX_PASSES
        saved, MAX_PASSES = MAX_PASSES, 1
        try:
            rc = cmd_sanitize(argparse.Namespace(paths=[ctx]), out=quiet)
        finally:
            MAX_PASSES = saved
        with open(ctx, encoding="utf-8") as fh:
            if rc != 1 or fh.read() != ctx_text:
                failures.append("a finding left after MAX_PASSES passes is not refused")
        if cmd_sanitize(argparse.Namespace(paths=[ctx]), out=quiet) != 0 or check_files([ctx]):
            failures.append("the second pass does not clear an exposed finding")

        # 12. A file that is not UTF-8 is refused by the check and by the sanitizer, untouched.
        blob = os.path.join(tmp, "blob.gz")
        with open(blob, "wb") as fh:
            fh.write(b"\x1f\x8b\x08\x00\xff\xfe")
        if check_files([blob]) != [f"  {blob}: unscannable: not UTF-8"]:
            failures.append("check accepts a non-UTF-8 file")
        if cmd_sanitize(argparse.Namespace(paths=[blob]), out=quiet) != 1:
            failures.append("sanitize accepts a non-UTF-8 file")
        with open(blob, "rb") as fh:
            if fh.read() != b"\x1f\x8b\x08\x00\xff\xfe":
                failures.append("sanitize wrote a non-UTF-8 file")

        # 13. A symbolic link is refused as itself by both halves, named or under a directory,
        #     and the file it names is neither read into a finding nor written.
        target = os.path.join(tmp, "outside.txt")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("clean\n")
        tree = os.path.join(tmp, "tree")
        os.makedirs(tree)
        link = os.path.join(tree, "oracle.txt")
        os.symlink(target, link)
        os.symlink(tmp, os.path.join(tree, "dirlink"))
        got = check_files(expand([tree]))
        want = [f"  {os.path.join(tree, 'dirlink')}: unscannable: a symbolic link",
                f"  {link}: unscannable: a symbolic link"]
        if got != want:
            failures.append(f"check of a tree with symbolic links: {got}")
        if check_files(expand([link])) != [want[1]]:
            failures.append("check follows a named symbolic link")
        if cmd_sanitize(argparse.Namespace(paths=[tree]), out=quiet) != 1:
            failures.append("sanitize accepts a symbolic link")

    # 14. The default scope is exactly the stated globs, and they are the routing row's.
    row = _routing_row_globs()
    if row != list(SCANNED_GLOBS):
        failures.append(f"routing row [{ROUTING_ROW}] globs {row} != SCANNED_GLOBS {list(SCANNED_GLOBS)}")
    for rel, want in (
        ("docs/evidence/runs/x/review.json", True),
        ("test/fixtures/workflows/a.json", True),
        ("crates/agent/tests/fixtures/fake.rs", True),
        ("bin/kata/tests/goldens/surface_inventory.json", True),
        ("crates/agent/src/adapter.rs", False),
        ("bin/kata/tests/cli_tests.rs", False),
        ("docs/product/operator-guide.md", False),
        ("scripts/evidence-sanitize.py", False),
        ("scripts/evidence-kit/ledger.py", True),
        ("vendor/x/test/a.rs", False),
    ):
        if in_scope(rel) != want:
            failures.append(f"scope of {rel}: {in_scope(rel)}, want {want}")

    # 15. The scan is linear in its input (the cases above `_scaling_cases`).
    failures.extend(_scaling_failures())

    if failures:
        print("evidence-sanitize self-test: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"evidence-sanitize self-test: PASS ({len(planted)} planted samples over "
        f"{len(names)} rules in {len(CLASSES)} classes refused; {CLEAN_CONTROLS.count(chr(10))} "
        f"control lines accepted; sanitizer output accepted and a fixed point, over the corpus and "
        f"{FUZZ_CASES} seeded random mixes; escaped JSONL stays valid; symbolic links and non-UTF-8 refused; "
        f"the scan linear over {len(_scaling_cases())} input shapes)"
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="cmd")
    p_check = sub.add_parser("check", help="refuse findings in the scanned set or in PATHs")
    p_check.add_argument("paths", nargs="*")
    p_san = sub.add_parser("sanitize", help="redact findings in place")
    p_san.add_argument("paths", nargs="+")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "sanitize":
        return cmd_sanitize(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
