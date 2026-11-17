//! A MOCK of the three reads `kata login status --check` makes, and of the
//! ChatGPT issuer a stale login refreshes against, on ONE loopback listener:
//!
//! * `GET /v1/models` answers `200` when the request presents the one API key
//!   the mock accepts, as OpenAI's API takes it (the `authorization` header's
//!   bearer) or as Anthropic's does (the `x-api-key` header beside an
//!   `anthropic-version` header), and `401` otherwise;
//! * `GET /backend-api/wham/usage` answers `200` when the bearer is an access
//!   token this mock accepts and the `chatgpt-account-id` header names its
//!   account, and `401` otherwise;
//! * `POST /oauth/token`, a JSON refresh grant presenting the current refresh
//!   token, mints a fresh access token (which the usage read then accepts) and
//!   a new refresh token; any other refresh token is refused `401`.
//!
//! Any other request is answered `404`. Every request is recorded (method,
//! path and lower-cased header names with their values), so a cell reads what
//! was presented from the mock, not from kata. It binds `127.0.0.1` only; no
//! cell built on it reaches a real provider. Every value it accepts or mints is
//! the mock's own, never a credential.
//!
//! Included by `#[path]` into `credential`'s cells, its only user.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use base64::Engine as _;

/// One request the mock received.
#[derive(Clone, Debug)]
pub struct Seen {
    /// `GET`, `POST`.
    pub method: String,
    /// The request target, query included.
    pub path: String,
    /// Header names lower-cased, each with its value.
    pub headers: BTreeMap<String, String>,
}

struct State {
    api_key: String,
    account: String,
    access: Vec<String>,
    refresh: String,
    serial: usize,
    seen: Vec<Seen>,
}

/// The running mock. Dropping it leaves the listener thread parked on
/// `accept`; it dies with the test process.
pub struct MockLoginCheck {
    /// `http://127.0.0.1:<port>`.
    pub url: String,
    state: Arc<Mutex<State>>,
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

/// An access token for `account` expiring at `exp` (Unix seconds).
pub fn chatgpt_token(account: &str, exp: i64, serial: usize) -> String {
    jwt(&serde_json::json!({
        "exp": exp,
        "serial": serial,
        "https://api.openai.com/auth": {"chatgpt_account_id": account},
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

impl MockLoginCheck {
    /// Start a mock accepting the API key `api_key`, the ChatGPT access tokens
    /// in `access` for `account`, and the refresh token `refresh`.
    pub fn start(api_key: &str, account: &str, access: &[String], refresh: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the mock");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State {
            api_key: api_key.to_owned(),
            account: account.to_owned(),
            access: access.to_vec(),
            refresh: refresh.to_owned(),
            serial: 0,
            seen: Vec::new(),
        }));
        let served = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = Arc::clone(&served);
                std::thread::spawn(move || serve(stream, &state));
            }
        });
        Self { url, state }
    }

    /// Every request received, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    /// The access tokens the issuer half minted.
    pub fn minted(&self) -> usize {
        self.state.lock().unwrap().serial
    }
}

fn serve(stream: std::net::TcpStream, state: &Mutex<State>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut words = request_line.split_whitespace();
    let method = words.next().unwrap_or_default().to_owned();
    let path = words.next().unwrap_or_default().to_owned();
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|length| length.parse().ok())
        .unwrap_or(0_usize);
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).unwrap();
    let mut state = state.lock().unwrap();
    state.seen.push(Seen {
        method: method.clone(),
        path: path.clone(),
        headers: headers.clone(),
    });
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_owned();
    let (status, answer) = match (method.as_str(), path.as_str()) {
        ("GET", "/v1/models") => {
            let openai = bearer == state.api_key;
            let anthropic = headers.get("x-api-key") == Some(&state.api_key)
                && headers.contains_key("anthropic-version");
            if openai || anthropic {
                ("200 OK", serde_json::json!({"data": []}))
            } else {
                (
                    "401 Unauthorized",
                    serde_json::json!({"error": "invalid_api_key"}),
                )
            }
        }
        ("GET", "/backend-api/wham/usage") => {
            if state.access.contains(&bearer)
                && headers.get("chatgpt-account-id") == Some(&state.account)
            {
                ("200 OK", serde_json::json!({}))
            } else {
                (
                    "401 Unauthorized",
                    serde_json::json!({"detail": "Unauthorized"}),
                )
            }
        }
        ("POST", "/oauth/token") => refresh(&body, &mut state),
        _ => ("404 Not Found", serde_json::json!({"error": "not_found"})),
    };
    drop(state);
    let answer = answer.to_string();
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{answer}",
        answer.len()
    );
}

fn refresh(body: &[u8], state: &mut State) -> (&'static str, serde_json::Value) {
    let request: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    if request["grant_type"] != "refresh_token" || request["refresh_token"] != *state.refresh {
        return (
            "401 Unauthorized",
            serde_json::json!({"error": "refresh_token_reused"}),
        );
    }
    state.serial += 1;
    state.refresh = format!("rt-{}", state.serial);
    let minted = chatgpt_token(&state.account, now_secs() + 3_600, state.serial);
    state.access.push(minted.clone());
    (
        "200 OK",
        serde_json::json!({
            "access_token": minted,
            // Borrowed: the mock's own `rt-<n>`, never a credential.
            "refresh_token": &state.refresh,
            "id_token": jwt(&serde_json::json!({
                "https://api.openai.com/auth": {"chatgpt_account_id": state.account},
            })),
        }),
    )
}
