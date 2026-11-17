//! A MOCK ChatGPT issuer on loopback that answers the device-code login the
//! way codex 0.165.0 talks to OpenAI's (`codex-rs/login/src/device_code_auth.rs`
//! and its wiremock suite `codex-rs/login/tests/suite/device_code_login.rs`):
//!
//! * `POST /api/accounts/deviceauth/usercode` with the JSON body
//!   `{"client_id": "<codex's client id>"}` answers
//!   `{"device_auth_id", "user_code", "interval": "<seconds, a STRING>"}`;
//! * `POST /api/accounts/deviceauth/token` with `{"device_auth_id",
//!   "user_code"}` answers `403` (or the script's `404`) while the code is not
//!   approved (codex reads `403` and `404` alike as "keep polling"), then
//!   `{"authorization_code", "code_challenge", "code_verifier"}`;
//! * `POST /oauth/token`, form-encoded, `grant_type=authorization_code` with
//!   that code, `redirect_uri=<issuer>/deviceauth/callback`, the client id and
//!   the verifier, answers `{"id_token", "access_token", "refresh_token"}`.
//!
//! A request to any other path is answered `404`, and a request to one of
//! these paths in any other shape `400`, so a client that sends another shape
//! cannot complete a login here. The issuer stamps
//! each poll's arrival, so a cell measures the interval the client keeps. It
//! binds `127.0.0.1` only; no cell built on it reaches a real issuer.
//!
//! Included by `#[path]` into `credential`'s cells, its only user.
#![allow(dead_code)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::Engine as _;

/// codex's OAuth client id (`codex-rs/login/src/auth/manager.rs`, `CLIENT_ID`).
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// The values this issuer hands out; each is the mock's own, never a credential.
pub const DEVICE_AUTH_ID: &str = "device-auth-123";
pub const USER_CODE: &str = "CODE-12345";
pub const AUTHORIZATION_CODE: &str = "poll-code-321";
pub const CODE_VERIFIER: &str = "code-verifier-321";
pub const ACCOUNT: &str = "acct-device";
pub const MINTED_REFRESH: &str = "rt-device";

/// How the issuer answers.
#[derive(Clone, Debug)]
pub struct Script {
    /// The code request's status (`404`: no device-code login here).
    pub usercode_status: u16,
    /// The `interval` it states, as codex's issuer spells it: a string.
    pub interval: &'static str,
    /// Polls answered "not approved yet" before the approval; `usize::MAX`
    /// never approves.
    pub pending_polls: usize,
    /// The status of each of those pending answers: `403`, or `404`, which
    /// codex reads alike.
    pub pending_status: u16,
    /// A status that answers every poll after the pending ones instead of the
    /// approval (e.g. `401`).
    pub poll_refusal: Option<u16>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            usercode_status: 200,
            interval: "1",
            pending_polls: 0,
            pending_status: 403,
            poll_refusal: None,
        }
    }
}

/// An unsigned JWT over `claims`; nanocode reads only the payload.
pub fn jwt(claims: &serde_json::Value) -> String {
    let encode = |value: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    };
    format!(
        "{}.{}.sig",
        encode(&serde_json::json!({"alg": "none"})),
        encode(claims)
    )
}

/// The access token this issuer mints for [`ACCOUNT`], expiring at `exp`
/// (Unix seconds).
pub fn access_token(exp: i64) -> String {
    jwt(&serde_json::json!({
        "exp": exp,
        "https://api.openai.com/auth": {"chatgpt_account_id": ACCOUNT},
    }))
}

/// Unix seconds now.
pub fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

#[derive(Default)]
struct Seen {
    usercodes: usize,
    polls: Vec<Instant>,
    exchanges: usize,
    minted_access: Option<String>,
}

/// The running mock. Dropping it leaves the listener thread parked on
/// `accept`; it dies with the test process.
pub struct MockDeviceIssuer {
    /// `http://127.0.0.1:<port>`.
    pub url: String,
    seen: Arc<Mutex<Seen>>,
}

impl MockDeviceIssuer {
    pub fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the mock issuer");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (thread_seen, thread_url) = (Arc::clone(&seen), url.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (seen, script, url) =
                    (Arc::clone(&thread_seen), script.clone(), thread_url.clone());
                std::thread::spawn(move || serve(stream, &script, &url, &seen));
            }
        });
        Self { url, seen }
    }

    /// Code requests answered.
    pub fn usercodes(&self) -> usize {
        self.seen.lock().unwrap().usercodes
    }

    /// Each poll's arrival.
    pub fn polls(&self) -> Vec<Instant> {
        self.seen.lock().unwrap().polls.clone()
    }

    /// Authorization codes exchanged for tokens.
    pub fn exchanges(&self) -> usize {
        self.seen.lock().unwrap().exchanges
    }

    /// The access token the exchange minted, if it ran.
    pub fn minted_access(&self) -> Option<String> {
        self.seen.lock().unwrap().minted_access.clone()
    }
}

fn serve(stream: std::net::TcpStream, script: &Script, url: &str, seen: &Mutex<Seen>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let (mut length, mut content_type) = (0_usize, String::new());
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap();
            } else if name.eq_ignore_ascii_case("content-type") {
                content_type = value.trim().to_owned();
            }
        }
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).unwrap();
    let json = || serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default();
    let (status, answer) = if request_line.starts_with("POST /api/accounts/deviceauth/usercode ") {
        usercode(script, &content_type, &json(), seen)
    } else if request_line.starts_with("POST /api/accounts/deviceauth/token ") {
        poll(script, &content_type, &json(), seen)
    } else if request_line.starts_with("POST /oauth/token ") {
        exchange(&content_type, &body, url, seen)
    } else {
        (404, serde_json::json!({"error": "not_found"}))
    };
    let answer = answer.to_string();
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{answer}",
        answer.len()
    );
}

fn bad_request(what: &str) -> (u16, serde_json::Value) {
    (
        400,
        serde_json::json!({"error": "invalid_request", "detail": what}),
    )
}

fn usercode(
    script: &Script,
    content_type: &str,
    body: &serde_json::Value,
    seen: &Mutex<Seen>,
) -> (u16, serde_json::Value) {
    if content_type != "application/json" || *body != serde_json::json!({"client_id": CLIENT_ID}) {
        return bad_request("usercode body");
    }
    seen.lock().unwrap().usercodes += 1;
    if script.usercode_status != 200 {
        return (script.usercode_status, serde_json::json!({}));
    }
    (
        200,
        serde_json::json!({
            "device_auth_id": DEVICE_AUTH_ID,
            "user_code": USER_CODE,
            "interval": script.interval,
        }),
    )
}

fn poll(
    script: &Script,
    content_type: &str,
    body: &serde_json::Value,
    seen: &Mutex<Seen>,
) -> (u16, serde_json::Value) {
    if content_type != "application/json"
        || *body != serde_json::json!({"device_auth_id": DEVICE_AUTH_ID, "user_code": USER_CODE})
    {
        return bad_request("poll body");
    }
    let mut seen = seen.lock().unwrap();
    seen.polls.push(Instant::now());
    if seen.polls.len() <= script.pending_polls {
        return (script.pending_status, serde_json::json!({}));
    }
    if let Some(status) = script.poll_refusal {
        return (status, serde_json::json!({}));
    }
    (
        200,
        serde_json::json!({
            "authorization_code": AUTHORIZATION_CODE,
            "code_challenge": "code-challenge-321",
            "code_verifier": CODE_VERIFIER,
        }),
    )
}

/// `application/x-www-form-urlencoded`, decoded.
fn form(body: &[u8]) -> Vec<(String, String)> {
    let decode = |text: &str| {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'+' => out.push(b' '),
                b'%' if index + 2 < bytes.len() => {
                    let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
                    out.push(u8::from_str_radix(hex, 16).unwrap());
                    index += 2;
                }
                byte => out.push(byte),
            }
            index += 1;
        }
        String::from_utf8(out).unwrap()
    };
    std::str::from_utf8(body)
        .unwrap()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (decode(name), decode(value)))
        .collect()
}

fn exchange(
    content_type: &str,
    body: &[u8],
    url: &str,
    seen: &Mutex<Seen>,
) -> (u16, serde_json::Value) {
    let mut fields = form(body);
    fields.sort();
    let mut expected = vec![
        ("client_id".to_owned(), CLIENT_ID.to_owned()),
        ("code".to_owned(), AUTHORIZATION_CODE.to_owned()),
        ("code_verifier".to_owned(), CODE_VERIFIER.to_owned()),
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        (
            "redirect_uri".to_owned(),
            format!("{url}/deviceauth/callback"),
        ),
    ];
    expected.sort();
    if content_type != "application/x-www-form-urlencoded" || fields != expected {
        return bad_request("code exchange form");
    }
    let minted = access_token(now_secs() + 3_600);
    let mut seen = seen.lock().unwrap();
    seen.exchanges += 1;
    seen.minted_access = Some(minted.clone());
    (
        200,
        serde_json::json!({
            "id_token": jwt(&serde_json::json!({
                "https://api.openai.com/auth": {"chatgpt_account_id": ACCOUNT},
            })),
            "access_token": &minted,
            "refresh_token": &MINTED_REFRESH,
        }),
    )
}
