//! A MOCK ChatGPT token issuer on loopback, for the cells of kata's own login.
//!
//! It answers `POST /oauth/token` refresh grants the way a rotating issuer
//! does: the one current refresh token is exchanged for a fresh access token
//! and a NEW refresh token, and any other refresh token (one already rotated)
//! is refused `401 refresh_token_reused`. It counts both. Each connection runs
//! on a thread of its own, so overlapping requests overlap here too: whatever
//! serializes two refreshes is the caller's, never the mock's. It binds
//! `127.0.0.1` only; no cell built on it reaches a real issuer.
//!
//! Included by `#[path]` into `agent_credential`'s cells, its only user, so a
//! change here routes to this crate; not every item is used by every cell.
#![allow(dead_code)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;

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
pub fn access_token(account: &str, exp: i64, serial: usize) -> String {
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

struct State {
    account: String,
    current_refresh: String,
    serial: usize,
}

/// The running mock. Dropping it leaves the listener thread parked on
/// `accept`; it dies with the test process.
pub struct MockIssuer {
    /// `http://127.0.0.1:<port>`.
    pub url: String,
    rotations: Arc<AtomicUsize>,
    reused: Arc<AtomicUsize>,
}

impl MockIssuer {
    /// Start an issuer for `account` whose current refresh token is
    /// `refresh_token`. Each rotation holds the issuer for `delay` first, so a
    /// second refresh in flight overlaps it.
    pub fn start(account: &str, refresh_token: &str, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the mock issuer");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State {
            account: account.to_owned(),
            current_refresh: refresh_token.to_owned(),
            serial: 0,
        }));
        let rotations = Arc::new(AtomicUsize::new(0));
        let reused = Arc::new(AtomicUsize::new(0));
        let (thread_rotations, thread_reused) = (Arc::clone(&rotations), Arc::clone(&reused));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let (state, rotations, reused) = (
                    Arc::clone(&state),
                    Arc::clone(&thread_rotations),
                    Arc::clone(&thread_reused),
                );
                std::thread::spawn(move || serve(stream, &state, &rotations, &reused, delay));
            }
        });
        Self {
            url,
            rotations,
            reused,
        }
    }

    /// Refresh tokens exchanged (each one a rotation).
    pub fn rotations(&self) -> usize {
        self.rotations.load(Ordering::SeqCst)
    }

    /// Already-rotated refresh tokens presented again.
    pub fn reused(&self) -> usize {
        self.reused.load(Ordering::SeqCst)
    }
}

fn serve(
    stream: std::net::TcpStream,
    state: &Mutex<State>,
    rotations: &AtomicUsize,
    reused: &AtomicUsize,
    delay: Duration,
) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut length = 0_usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).unwrap();
    let (status, answer) = if request_line.starts_with("POST /oauth/token ") {
        refresh(&body, state, rotations, reused, delay)
    } else {
        ("404 Not Found", serde_json::json!({"error": "not_found"}))
    };
    let answer = answer.to_string();
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{answer}",
        answer.len()
    );
}

fn refresh(
    body: &[u8],
    state: &Mutex<State>,
    rotations: &AtomicUsize,
    reused: &AtomicUsize,
    delay: Duration,
) -> (&'static str, serde_json::Value) {
    let request: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let presented = request["refresh_token"].as_str().unwrap_or_default();
    // Held across the delay: the issuer judges one presented token at a time,
    // as a real one does, so a second token presented meanwhile is judged
    // against the rotation the first one made.
    let mut state = state.lock().unwrap();
    if request["grant_type"] != "refresh_token" || presented != state.current_refresh {
        reused.fetch_add(1, Ordering::SeqCst);
        return (
            "401 Unauthorized",
            serde_json::json!({"error": "refresh_token_reused"}),
        );
    }
    std::thread::sleep(delay);
    state.serial += 1;
    state.current_refresh = format!("rt-{}", state.serial);
    rotations.fetch_add(1, Ordering::SeqCst);
    (
        "200 OK",
        serde_json::json!({
            "access_token": access_token(&state.account, now_secs() + 3_600, state.serial),
            // Borrowed: `scripts/evidence-sanitize.py` reads a bare name after this
            // key as a token value (a SCALAR), and the value is this mock's own
            // `rt-<n>`, never a credential.
            "refresh_token": &state.current_refresh,
            "id_token": jwt(&serde_json::json!({
                "https://api.openai.com/auth": {"chatgpt_account_id": state.account},
            })),
        }),
    )
}
