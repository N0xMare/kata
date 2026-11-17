//! Regression coverage for the SDK's own transport bounds.
//!
//! ## What broke, and why the fix needs a test at this layer
//!
//! `smoke_product_cli_init_main_submit_watch_wait_output_shutdown` timed out at
//! nextest's 300s kill inside the containment gate tier, twice, while
//! passing in 1.26s in isolation. The cause was not slowness: it was that every
//! wait between the smoke and the socket was unbounded, so nextest's runner-level
//! kill was the FIRST bound in the stack and it can only report "timed out"
//! without naming a subject. `KataClient` was the innermost of those layers —
//! fifty-odd `pub async fn`s, exactly one of which
//! (`system_status_bounded`) set a deadline.
//!
//! These tests pin the three properties that make that unfixable-by-accident:
//!
//! 1. the default client actually carries a read bound (a bound nobody applies
//!    is a comment);
//! 2. the bound, when it trips, produces a message that names the layer and the
//!    operation — the whole point, since a bare "timed out" is what cost three
//!    encounters to diagnose;
//! 3. the bound stays compatible with the server's SSE keep-alive contract,
//!    which is the one consumer a naive total-request timeout would have
//!    broken.

use std::time::Duration;

use kata_api::rest::events::SSE_KEEP_ALIVE_INTERVAL;
use kata_client::{KataClient, KataClientError};
use tokio::net::TcpListener;

/// Bind a loopback listener that ACCEPTS connections and then answers nothing,
/// ever. This is the failure mode that defeats a connect timeout, defeats a
/// TCP-level health check, and looks exactly like a healthy server to a client
/// with no read bound.
///
/// The accept loop is held in a spawned task; dropping the returned
/// `JoinHandle` guard at end of test tears it down.
async fn accept_and_stall() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stall listener");
    let addr = listener.local_addr().expect("stall listener addr");
    let handle = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            // Hold the accepted socket open and never write a byte. Dropping it
            // would send FIN and let the client fail fast for the wrong reason.
            held.push(stream);
        }
    });
    (format!("http://{addr}"), handle)
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread")]
async fn a_socket_that_accepts_and_never_answers_trips_the_read_bound_with_a_named_message() {
    let (base_url, listener) = accept_and_stall().await;

    // A 250ms read bound stands in for `KataClient::DEFAULT_READ_TIMEOUT` so the
    // test costs a quarter-second instead of 31 seconds. The bound's VALUE is
    // asserted separately below; what is proved here is the behavior and the
    // message, which are value-independent.
    let http = KataClient::http_builder()
        .read_timeout(Duration::from_millis(250))
        .build()
        .expect("build short-bound client");
    let client = KataClient::with_http(&base_url, http).expect("client");

    let started = std::time::Instant::now();
    let err = client
        .health()
        .await
        .expect_err("a socket that never answers must not resolve to a health snapshot");
    let elapsed = started.elapsed();

    let KataClientError::TransportStalled { phase, url } = &err else {
        panic!("a read-bound trip must surface as TransportStalled, got: {err:?}");
    };
    assert_eq!(
        *phase, "response",
        "the connection was established, so the stall is in the response phase"
    );
    assert!(
        url.ends_with("/api/v1/health"),
        "the message must name the OPERATION, and the request path is it: {url}"
    );

    // The rendered message is the artifact an operator or a CI log actually
    // sees, so assert on it rather than only on the variant.
    let rendered = err.to_string();
    assert!(
        rendered.contains("kata-client transport"),
        "the message must name the LAYER that stopped waiting: {rendered}"
    );
    assert!(
        rendered.contains(&base_url),
        "the message must name the endpoint it gave up on: {rendered}"
    );

    assert!(
        elapsed < Duration::from_secs(5),
        "the bound must fail FAST — that is the whole point — but took {elapsed:?}"
    );
    listener.abort();
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread")]
async fn a_black_holed_connect_is_reported_as_the_connect_phase_not_the_response_phase() {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): guaranteed not to be routed to a
    // real host, so the SYN goes nowhere and the kernel retransmits. Without a
    // connect bound this call would sit for over two minutes.
    let http = KataClient::http_builder()
        .connect_timeout(Duration::from_millis(250))
        .build()
        .expect("build short-connect client");
    let client = KataClient::with_http("http://192.0.2.1:8400", http).expect("client");

    let started = std::time::Instant::now();
    let err = client
        .health()
        .await
        .expect_err("an unroutable address cannot answer");
    let elapsed = started.elapsed();

    let KataClientError::TransportStalled { phase, url } = &err else {
        panic!("a connect-bound trip must surface as TransportStalled, got: {err:?}");
    };
    assert_eq!(
        *phase, "connect",
        "a stall BEFORE the connection exists is a network-path problem, not a server problem, \
         and the message must not blame the wrong owner"
    );
    assert!(
        url.contains("192.0.2.1"),
        "the message must name the endpoint: {url}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the connect bound must fail fast, took {elapsed:?}"
    );
}

#[test]
fn the_default_client_carries_a_read_bound_and_the_agent_run_client_does_not() {
    let client = KataClient::new("http://127.0.0.1:8400").expect("client");
    // `reqwest::Client`'s Debug prints `read_timeout` only when one is set, so
    // this is the one externally observable proof that the builder applied it.
    // `ClientInner` holds exactly two reqwest clients, so a single occurrence
    // means: bounded for the ordinary methods, unbounded for the carve-outs
    // (`run_agent`, whose server side deliberately has no deadline either;
    // `forge_reconcile`, bounded by the server's per-command deadlines; and
    // `invoke_op`'s `run` and `forge_reconcile`, whose server bounds its own wait).
    let rendered = format!("{client:?}");
    let occurrences = rendered.matches("read_timeout").count();
    assert_eq!(
        occurrences, 1,
        "expected exactly one bounded inner client (0 = the default client is unbounded again; \
         2 = run_agent lost its carve-out and will now be killed mid-model-run): {rendered}"
    );
    assert!(
        rendered.contains(&format!("{:?}", KataClient::DEFAULT_READ_TIMEOUT)),
        "the applied bound must be the documented default: {rendered}"
    );
}

#[test]
fn the_client_read_bound_survives_a_lost_server_keep_alive() {
    // The SSE subscription is the consumer that makes a TOTAL request deadline
    // impossible and an INACTIVITY deadline safe: a healthy but idle stream
    // still writes a keep-alive comment every `SSE_KEEP_ALIVE_INTERVAL`.
    //
    // Strictly greater than two intervals, not "at least": at exactly two the
    // deadline and the second keep-alive are scheduled for the same instant and
    // the winner is whichever timer the runtime polls first — a coin flip on a
    // loaded host, i.e. a flake.
    assert!(
        KataClient::DEFAULT_READ_TIMEOUT > SSE_KEEP_ALIVE_INTERVAL * 2,
        "a client read bound of {:?} cannot tolerate even ONE lost keep-alive at a server \
         interval of {SSE_KEEP_ALIVE_INTERVAL:?}; every quiet `kata watch` would report a \
         transport failure",
        KataClient::DEFAULT_READ_TIMEOUT,
    );
    // And bounded above, so the bound stays a bound: a read deadline that
    // exceeds the 60s nextest slow-timeout would let a stalled request outlive
    // the runner's own patience and hand back an unattributable kill again.
    assert!(
        KataClient::DEFAULT_READ_TIMEOUT < Duration::from_secs(60),
        "the read bound must trip before nextest's 60s slow tick so the failure is ATTRIBUTED"
    );
}

#[test]
fn the_connect_bound_cuts_the_syn_ladder_between_the_third_and_fourth_attempt() {
    // Linux retransmits SYNs on an exponential RTO, so attempts land at
    // t = 0s, 1s, 3s, 7s, 15s, 31s, 63s. A bound in (3s, 7s] admits the first
    // three — enough that a single lost packet still recovers — and expires as
    // the fourth would go out, instead of waiting out the full ~130s ladder.
    assert!(
        KataClient::DEFAULT_CONNECT_TIMEOUT > Duration::from_secs(3),
        "a connect bound at or below the third SYN turns one lost packet into a hard failure"
    );
    assert!(
        KataClient::DEFAULT_CONNECT_TIMEOUT <= Duration::from_secs(7),
        "past the fourth SYN the bound stops being cheaper than the kernel's own ladder"
    );
    assert!(
        KataClient::DEFAULT_CONNECT_TIMEOUT < KataClient::DEFAULT_READ_TIMEOUT,
        "connect must fail before read so the reported PHASE names the right owner"
    );
}

/// Set in the child process [`the_client_trusts_the_hosts_certificate_store`]
/// re-executes this test binary as.
const EMPTY_TRUST_STORE_CHILD: &str = "KATA_CLIENT_EMPTY_TRUST_STORE_CHILD";

/// The SDK's TLS trusts the HOST's certificate store, never a root bundle of its
/// own: kata inherits the host's answer and refuses when there is none.
///
/// Proven against the environment rather than against kata. This process (the
/// host's own store) must build a client; a child of this same test binary whose
/// ONLY trust store is an empty file (`SSL_CERT_FILE=/dev/null`, which the host
/// store loader reads instead of the system store) must be REFUSED one, before
/// any request and for an `http://` base URL. A bundle compiled into the SDK
/// would ignore `SSL_CERT_FILE` and build in both.
#[test]
fn the_client_trusts_the_hosts_certificate_store() {
    const BASE_URL: &str = "http://127.0.0.1:9";
    if std::env::var_os(EMPTY_TRUST_STORE_CHILD).is_some() {
        let refused = KataClient::new(BASE_URL)
            .expect_err("a host whose trust store holds no certificate must be refused a client");
        assert!(
            matches!(refused, KataClientError::HttpClientBuild(_)),
            "the refusal must name the client build, got: {refused:?}"
        );
        return;
    }

    KataClient::new(BASE_URL).expect("the host's own trust store builds a client");

    let child = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "the_client_trusts_the_hosts_certificate_store",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(EMPTY_TRUST_STORE_CHILD, "1")
        .env("SSL_CERT_FILE", "/dev/null")
        .env_remove("SSL_CERT_DIR")
        .output()
        .expect("re-execute this test binary with an empty trust store");
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert!(
        child.status.success() && stdout.contains("1 passed"),
        "with an empty host trust store the SDK still built a client — it trusts roots \
         the host did not give it.\nstatus: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        child.status
    );
}

/// Bind a loopback listener that answers every request with `body` — but only after
/// sitting SILENT for `silence`, the way `POST /ops/run` with `wait` sits until its
/// bounded wait ends and `POST /ops/forge_reconcile` sits until every export is driven.
/// Each connection reads one request head and its body (by `Content-Length`) first, so
/// the client's request is fully sent before the silence starts.
async fn answer_after_silence(
    silence: Duration,
    body: &'static str,
) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent listener");
    let addr = listener.local_addr().expect("silent listener addr");
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&request);
                    let Some(head_end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let length = text[..head_end]
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    if request.len() >= head_end + 4 + length {
                        break;
                    }
                }
                tokio::time::sleep(silence).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                     connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), handle)
}

/// `KataClient::invoke_op` relays the two operations whose server writes NOTHING until a
/// bounded-but-long wait ends — `run` (compile + submit + `wait_timeout_secs` up to
/// `MAX_RUN_WAIT_SECS`) and `forge_reconcile` (the server's per-command deadlines) — and
/// must outlast that silence. The default client's inactivity bound
/// (`DEFAULT_READ_TIMEOUT`) cut a `run` the contract allows at 31 s, AFTER the execution
/// was admitted; `kata mcp`'s attached binding then answered the agent with a retryable
/// network error and a retry submitted a second execution.
///
/// Every other operation answers without a wait and keeps the bound: an `observe` made
/// beside them against the same silence must still stall at `DEFAULT_READ_TIMEOUT`.
///
/// The witness is a socket that does not share the SDK's code: it answers every request
/// after `DEFAULT_READ_TIMEOUT` plus two seconds of silence. The calls are made
/// concurrently, so the cell costs one silence, not three.
#[kata_test_utils::kata_timeout(secs = 50)]
#[tokio::test(flavor = "multi_thread")]
async fn invoke_op_outlasts_the_silence_of_an_operation_whose_server_waits_before_answering() {
    const ENVELOPE: &str = r#"{"op":"run","schema_version":1,"ok":true,"data":{}}"#;
    let silence = KataClient::DEFAULT_READ_TIMEOUT + Duration::from_secs(2);
    let (base_url, listener) = answer_after_silence(silence, ENVELOPE).await;
    let client = KataClient::new(&base_url).expect("client");

    let arguments = serde_json::json!({});
    let (run, reconcile, observe) = tokio::join!(
        client.invoke_op("run", &arguments),
        client.invoke_op("forge_reconcile", &arguments),
        client.invoke_op("observe", &arguments),
    );
    let run = run.expect(
        "a `run` whose server is silent past DEFAULT_READ_TIMEOUT must still be answered: the \
         silence is the bounded wait the request asked for",
    );
    assert_eq!(run["ok"], true, "the relayed envelope: {run}");
    reconcile.expect(
        "a `forge_reconcile` whose server is silent past DEFAULT_READ_TIMEOUT must still be \
         answered: the server's per-command deadlines bound it",
    );
    let observe = observe.expect_err(
        "an `observe` answers without a wait, so silence past DEFAULT_READ_TIMEOUT is a stall",
    );
    assert!(
        matches!(
            observe,
            KataClientError::TransportStalled {
                phase: "response",
                ..
            }
        ),
        "an `observe` keeps the SDK's read bound: {observe:?}"
    );
    listener.abort();
}
