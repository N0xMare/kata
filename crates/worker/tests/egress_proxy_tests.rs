//! Every refusal `kata_worker::egress_proxy` claims,
//! scored from OUTSIDE the proxy.
//!
//! # How a refusal is scored here
//!
//! Two independent observations per refused row, and neither of them asks the proxy
//! whether it refused:
//!
//! 1. **The upstream side, for the PRE-CONNECT arms.** A real `tokio::net::TcpListener`
//!    is bound on loopback and the cell asserts it NEVER accepts a connection. This
//!    applies to the refusals decided before `TcpStream::connect` — the parse arms, the
//!    allowlist arms, both caps and the spent total budget. It is NOT the observation
//!    for `upstream_unreachable` (whose whole content is that a connect was attempted
//!    and failed) or for the in-tunnel arms (`connection_byte_budget`, `idle_timeout`),
//!    which are scored off the client socket's EOF and the relayed byte counts instead.
//!    A pre-connect refusal that recorded itself and connected anyway — the "guarantee
//!    wider than its mechanism" defect in its egress form — is red here.
//! 2. **The client side.** The status line the client reads, plus the
//!    `X-Kata-Egress-Refused` label, both read off the socket.
//!
//! The recorded refusal is checked too, as a THIRD assertion, never as the only one.
//!
//! # Would these pass against a stub?
//!
//! A stub that refused everything passes the twelve refusal cells and fails
//! [`a_tunnel_relays_bytes_both_ways`], [`the_total_budget_admits_the_first_tunnel`]
//! and [`teardown_closes_a_live_tunnel`], each of which requires bytes to have
//! crossed a real `CONNECT` tunnel to a real listener. A stub that allowed everything
//! fails every refusal cell on the upstream observation alone.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::Duration;

use kata_agent::resource_bounds::{TeardownOutcome, TeardownProbe};
use kata_types::egress_refusal::EgressRefusalKind;
use kata_worker::egress_handoff::{HandoffRefusal, Receiver};
use kata_worker::egress_proxy::{
    EgressAllowlist, EgressBudgets, EgressPlumbing, EgressProxy, EgressRefusal,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// How long an upstream listener is watched before "it never accepted" is believed.
///
/// A negative observation needs a window, and this one is generous relative to a
/// loopback connect (microseconds) while staying far inside the suite's slow-timeout.
const NEVER_ACCEPTS_WINDOW: Duration = Duration::from_millis(250);

/// Budgets wide enough that no cell trips one it did not mean to.
fn wide() -> EgressBudgets {
    EgressBudgets {
        max_concurrent: 8,
        max_pending: 32,
        per_connection_bytes: 1 << 20,
        total_bytes: 1 << 20,
        idle: Duration::from_secs(10),
        max_request_line_bytes: 8 * 1024,
        max_header_block_bytes: 16 * 1024,
    }
}

/// A bound loopback listener nothing has connected to yet.
async fn upstream() -> (TcpListener, u16) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("loopback is bindable in the test process");
    let port = listener.local_addr().expect("a bound address").port();
    (listener, port)
}

/// A loopback port nothing listens on, so every connect to it is refused: port 1,
/// below `net.ipv4.ip_unprivileged_port_start` (1024 by default), so no unprivileged
/// process — no other cell's `upstream` in a parallel run — can bind it. A port read
/// off a dropped listener is free for the next bind to take, and the dial would then
/// open a tunnel to whichever listener took it.
const CLOSED_PORT: u16 = 1;

/// Write one raw request and read the whole response head back.
async fn exchange(proxy: &EgressProxy, request: &str) -> String {
    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy's listener accepts");
    client
        .write_all(request.as_bytes())
        .await
        .expect("the request is writable");
    let mut head = Vec::new();
    // Read to EOF: every refusal answers and then shuts the socket down, so EOF is
    // the frame boundary and no length has to be guessed.
    client
        .read_to_end(&mut head)
        .await
        .expect("a refused client is answered and closed");
    String::from_utf8_lossy(&head).into_owned()
}

/// The minimal well-formed `CONNECT` for an authority.
fn connect_request(authority: &str) -> String {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
}

/// Assert the listener accepts nothing inside [`NEVER_ACCEPTS_WINDOW`].
async fn never_accepts(listener: &TcpListener, why: &str) {
    assert!(
        tokio::time::timeout(NEVER_ACCEPTS_WINDOW, listener.accept())
            .await
            .is_err(),
        "the upstream listener must never see a connection: {why}. A refusal recorded on kata's \
         side while the bytes reached the network is an egress bound that does not bound egress"
    );
}

/// Every label recorded so far.
async fn labels(proxy: &EgressProxy) -> Vec<&'static str> {
    proxy
        .refusals()
        .await
        .iter()
        .map(EgressRefusal::label)
        .collect()
}

/// The test's upstream dial: a real `TcpStream::connect` to what the request
/// named, WITHOUT the connect-time address policy — the policy refuses every
/// address class a test can bind (loopback first of all), which is the whole
/// point of it, so a cell that needs a TUNNEL cannot go through it. The stub
/// changes where the connect lands and nothing else: the parse, the allowlist
/// match, the caps, the budgets and the relay are all the production body —
/// which is why the refused set below runs the REAL dialer
/// (`policy_proxy`) and these cells cannot prove it. What a dial failure
/// becomes is still honest here: a refused loopback connect maps to
/// `UpstreamUnreachable`, exactly as `connect_checked` maps it.
fn loopback_dial(
    host: &str,
    port: u16,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<TcpStream, EgressRefusal>> + Send + '_>,
> {
    let authority = format!("{host}:{port}");
    Box::pin(async move {
        TcpStream::connect((host, port))
            .await
            .map_err(|error| EgressRefusal::UpstreamUnreachable {
                authority,
                error: error.to_string(),
            })
    })
}

/// A proxy whose allowlist admits exactly `127.0.0.1:<port>`, accepting on a
/// host loopback listener the way the drive accepts on the handed-over guest
/// fd — same accept source, same `serve` body.
async fn proxy_for(port: u16, budgets: EgressBudgets) -> EgressProxy {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("the proxy's accept source binds on loopback");
    EgressProxy::accept_on_dialing(
        listener,
        EgressAllowlist::exact([("127.0.0.1", port)]).expect("an exact pair"),
        budgets,
        loopback_dial,
    )
    .expect("sane budgets")
}

/// A proxy on the REAL dial path — `accept_on` runs `connect_checked`, so the
/// connect-time address policy is live in exactly the way it is in production.
/// The refused-set cells for `egress_address_refused` use this one: their
/// upstream is a listener the guest must never reach, and the guest still
/// can't.
async fn policy_proxy(entries: &[(&str, u16)]) -> EgressProxy {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("the proxy's accept source binds on loopback");
    EgressProxy::accept_on(
        listener,
        EgressAllowlist::exact(entries.iter().copied()).expect("exact pairs"),
        wide(),
    )
    .expect("sane budgets")
}

// ---------------------------------------------------------------------------
// The refused set, one cell per arm
// ---------------------------------------------------------------------------

/// **A non-`CONNECT` request is refused and the upstream never sees a connection.**
#[tokio::test]
async fn a_non_connect_method_is_refused() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let head = exchange(
        &proxy,
        &format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: x\r\n\r\n"),
    )
    .await;

    assert!(
        head.starts_with("HTTP/1.1 405 Method Not Allowed"),
        "a forwarding proxy is what this refuses to be; got {head:?}"
    );
    assert!(head.contains("X-Kata-Egress-Refused: method_not_connect"));
    never_accepts(&listener, "the method was not CONNECT").await;
    assert_eq!(labels(&proxy).await, vec!["method_not_connect"]);
    assert_eq!(proxy.opened_tunnels(), 0);
}

/// **A host absent from the allowlist is refused, and the STRING match happens before
/// any resolution.**
///
/// The foreign host is `localhost`, which resolves to the very address the allowed entry
/// names and the upstream listener is bound to — so a proxy that resolved first and
/// matched on the address WOULD have connected here. (A `127.0.0.2` spelling made the
/// never-accepts half vacuous: nothing is listening there, so it could not have accepted
/// however the proxy behaved.) Which also pins the allowlist's semantics in one
/// assertion: an entry is trust in the NAME, and a different name for the same address
/// is a different entry.
#[tokio::test]
async fn a_host_outside_the_allowlist_is_refused() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let head = exchange(&proxy, &connect_request(&format!("localhost:{port}"))).await;

    assert!(head.starts_with("HTTP/1.1 403 Forbidden"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: host_not_allowed"));
    never_accepts(
        &listener,
        "`localhost` is not the allowlisted name, even though it resolves to the address the \
         allowlisted name does",
    )
    .await;
    assert_eq!(labels(&proxy).await, vec!["host_not_allowed"]);
}

/// **An allowed host on a port the allowlist does not carry is refused, and says so
/// as a PORT refusal.**
///
/// The distinction is the operator's next action: add a port to an entry, or add an
/// entry. A single `host_not_allowed` for both would name the wrong one.
#[tokio::test]
async fn an_allowed_host_on_a_foreign_port_is_refused_as_a_port() {
    let (listener, port) = upstream().await;
    let (other_listener, other_port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let head = exchange(&proxy, &connect_request(&format!("127.0.0.1:{other_port}"))).await;

    assert!(head.starts_with("HTTP/1.1 403 Forbidden"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: port_not_allowed"));
    never_accepts(&other_listener, "the port is not on the allowlist").await;
    never_accepts(&listener, "and neither is the allowed port reached instead").await;
    assert_eq!(labels(&proxy).await, vec!["port_not_allowed"]);
}

/// **An allowed authority whose upstream refuses the connection is a 502, recorded as
/// an upstream failure and not as an allowlist refusal.**
#[tokio::test]
async fn an_unreachable_upstream_is_its_own_refusal() {
    let port = CLOSED_PORT;
    let proxy = proxy_for(port, wide()).await;

    let head = exchange(&proxy, &connect_request(&format!("127.0.0.1:{port}"))).await;

    assert!(head.starts_with("HTTP/1.1 502 Bad Gateway"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: upstream_unreachable"));
    assert_eq!(labels(&proxy).await, vec!["upstream_unreachable"]);
    assert_eq!(
        proxy.opened_tunnels(),
        0,
        "a tunnel that never connected was never opened"
    );
    assert_eq!(
        proxy.live_tunnels(),
        0,
        "the concurrency slot taken before the connect must be released on its failure"
    );
}

// ---------------------------------------------------------------------------
// The connect-time address policy — the refused set, by class
// ---------------------------------------------------------------------------

/// **Every address class `resolved_address_policy` names is refused at CONNECT
/// — a 403 recorded as `egress_address_refused`, with the target never dialed.**
///
/// One row per refused class on the REAL dial path (`policy_proxy` runs
/// `connect_checked`): the allowlist carries the literal itself, so the refusal
/// cannot be a resolution artifact, and the recorded refusal must name the
/// address that was refused — a refusal that dialed anyway, or refused some
/// OTHER address than the one asked for, is the "wider than its mechanism"
/// defect in its egress form.
///
/// # Would red if
///
/// Any class fell out of `refuse_v4`/`refuse_v6` — an edited table is how this
/// cell proves the class list, rather than the shape of the refusal alone. The
/// v4-mapped v6 form is a row too, because laundering is the point of it.
#[tokio::test]
async fn every_unsafe_address_class_is_refused_at_connect() {
    // (authority host as the allowlist and the CONNECT spell it, a word its
    // refusal's `why` must carry). Literals only: `lookup_host` returns them
    // verbatim, so a row cannot flake on a resolver.
    for (host, named) in [
        ("127.0.0.9", "loopback"),
        ("10.9.9.9", "RFC 1918"),
        ("172.16.9.9", "RFC 1918"),
        ("192.168.9.9", "RFC 1918"),
        ("169.254.169.254", "link-local"),
        ("100.64.9.9", "shared"),
        ("0.9.9.9", "this network"),
        ("224.0.0.9", "multicast"),
        ("192.0.0.9", "192.0.0.0/24"),
        ("192.88.99.9", "192.88.99.0/24"),
        ("192.0.2.9", "documentation"),
        ("198.51.100.9", "documentation"),
        ("203.0.113.9", "documentation"),
        ("198.18.9.9", "benchmarking"),
        ("240.9.9.9", "reserved"),
        ("255.255.255.255", "broadcast"),
        ("[::1]", "loopback"),
        ("[::]", "unspecified"),
        ("[fe80::9]", "link-local"),
        ("[fd00::9]", "unique-local"),
        ("[ff02::9]", "multicast"),
        ("[2001:db8::9]", "documentation"),
        ("[::ffff:127.0.0.9]", "v4-mapped"),
    ] {
        let proxy = policy_proxy(&[(host, 443)]).await;

        let head = exchange(&proxy, &connect_request(&format!("{host}:443"))).await;

        assert!(
            head.starts_with("HTTP/1.1 403 Forbidden"),
            "{host}: the address classes are POLICY refusals, answered as 403 — got {head:?}"
        );
        assert!(
            head.contains("X-Kata-Egress-Refused: egress_address_refused"),
            "{host}: refused by name, not by an allowlist miss — got {head:?}"
        );
        let refusals = proxy.refusals().await;
        let [EgressRefusal::EgressAddressRefused { resolved, why, .. }] = refusals.as_slice()
        else {
            panic!("{host}: the recorded refusal is the address-policy arm, got {refusals:?}");
        };
        assert!(
            why.contains(named),
            "{host}: the refusal names its class `{named}` so an operator reads why the address \
             is not a destination: {why}"
        );
        assert!(
            resolved.contains(host.trim_start_matches('[').trim_end_matches(']')),
            "{host}: the record names the addresses the name resolved to — it must be the asked \
             address, not a neighbour: {resolved}"
        );
        assert_eq!(
            proxy.opened_tunnels(),
            0,
            "{host}: a refused connect cannot have opened a tunnel"
        );
        drop(proxy.close().await);
    }
}

/// **A loopback upstream is refused before it can ever be connected to — the
/// listener at the very allowlisted endpoint watches nothing arrive.**
///
/// The strongest form of the class cell above: the upstream listener IS the
/// address the allowlist names, and it still sees nothing — which is the whole
/// claim, since loopback is where the WORKER's own services live.
#[tokio::test]
async fn a_loopback_upstream_is_refused_before_it_can_accept() {
    let (listener, port) = upstream().await;
    let proxy = policy_proxy(&[("127.0.0.1", port)]).await;

    let head = exchange(&proxy, &connect_request(&format!("127.0.0.1:{port}"))).await;

    assert!(head.starts_with("HTTP/1.1 403 Forbidden"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: egress_address_refused"));
    never_accepts(
        &listener,
        "127.0.0.1 is refused as an ADDRESS, not as a name — the allowlist's literal resolves to \
         the listener and the connect still cannot happen",
    )
    .await;
    assert_eq!(labels(&proxy).await, vec!["egress_address_refused"]);
    drop(proxy.close().await);
}

/// **`::ffff:127.0.0.1` cannot launder the loopback past a v6-only check — the
/// mapped form is refused under the SAME v4 rules.**
#[tokio::test]
async fn a_v4_mapped_address_cannot_launder_loopback() {
    let (listener, port) = upstream().await;
    let proxy = policy_proxy(&[("[::ffff:127.0.0.1]", port)]).await;

    let head = exchange(
        &proxy,
        &connect_request(&format!("[::ffff:127.0.0.1]:{port}")),
    )
    .await;

    assert!(head.starts_with("HTTP/1.1 403 Forbidden"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: egress_address_refused"));
    never_accepts(
        &listener,
        "the mapped form names THIS listener's address and must still not reach it",
    )
    .await;
    assert_eq!(labels(&proxy).await, vec!["egress_address_refused"]);
    drop(proxy.close().await);
}

/// **A request line with no CRLF inside the cap is refused, without the cap's worth
/// of bytes being buffered into anything unbounded.**
#[tokio::test]
async fn an_unterminated_request_line_is_refused_at_the_cap() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.max_request_line_bytes = 64;
    let proxy = proxy_for(port, budgets).await;

    let head = exchange(&proxy, &"A".repeat(4096)).await;

    assert!(
        head.starts_with("HTTP/1.1 414 URI Too Long"),
        "got {head:?}"
    );
    assert!(head.contains("X-Kata-Egress-Refused: request_line_too_long"));
    never_accepts(&listener, "nothing was ever parsed").await;
    assert_eq!(labels(&proxy).await, vec!["request_line_too_long"]);
}

/// **A header block past its cap is refused, separately from the request line.**
#[tokio::test]
async fn a_header_block_past_its_cap_is_refused() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.max_header_block_bytes = 64;
    let proxy = proxy_for(port, budgets).await;

    let mut request = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n");
    let padding = "p".repeat(32);
    for index in 0..16 {
        write!(request, "X-Pad-{index}: {padding}\r\n").expect("a String write cannot fail");
    }
    request.push_str("\r\n");
    let head = exchange(&proxy, &request).await;

    assert!(
        head.starts_with("HTTP/1.1 431 Request Header Fields Too Large"),
        "got {head:?}"
    );
    assert!(head.contains("X-Kata-Egress-Refused: header_block_too_large"));
    never_accepts(&listener, "the header block never finished").await;
    assert_eq!(labels(&proxy).await, vec!["header_block_too_large"]);
}

/// **An obs-fold continuation line is refused rather than joined.**
///
/// RFC 9112 forbids it, and two parsers that disagree about whether a folded line
/// continues the previous header is the classic request-smuggling primitive. This
/// proxy has exactly one answer.
#[tokio::test]
async fn a_folded_header_is_refused() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let head = exchange(
        &proxy,
        &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: a\r\n\tcontinued\r\n\r\n"),
    )
    .await;

    assert!(head.starts_with("HTTP/1.1 400 Bad Request"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: folded_header"));
    never_accepts(&listener, "a folded header ends the request").await;
    assert_eq!(labels(&proxy).await, vec!["folded_header"]);
}

/// **A `CONNECT` target that is not `host:port` is refused, and no default port is
/// invented for it.**
#[tokio::test]
async fn a_target_without_a_port_is_refused() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let head = exchange(&proxy, &connect_request("127.0.0.1")).await;

    assert!(head.starts_with("HTTP/1.1 400 Bad Request"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: malformed_authority"));
    never_accepts(&listener, "no port was named, and none is defaulted").await;
    assert_eq!(labels(&proxy).await, vec!["malformed_authority"]);
}

/// **A malformed request line is refused as a request line, not as an authority.**
#[tokio::test]
async fn a_two_token_request_line_is_refused() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let head = exchange(&proxy, &format!("CONNECT 127.0.0.1:{port}\r\n\r\n")).await;

    assert!(head.starts_with("HTTP/1.1 400 Bad Request"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: malformed_request_line"));
    never_accepts(&listener, "the request line never parsed").await;
    assert_eq!(labels(&proxy).await, vec!["malformed_request_line"]);
}

/// **The concurrency cap refuses the tunnel that would exceed it, BEFORE the upstream
/// connect.**
///
/// The upstream sees exactly ONE accepted connection while two clients are waiting,
/// which is the observation that separates a cap from a queue.
#[tokio::test]
async fn the_concurrency_cap_refuses_before_connecting() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.max_concurrent = 1;
    let proxy = proxy_for(port, budgets).await;

    // Tunnel one, left OPEN: connect, read the established line, relay nothing.
    let mut first_tunnel = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    first_tunnel
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .await
        .expect("writable");
    let accepted = listener
        .accept()
        .await
        .expect("the upstream is connected to");
    let mut established = [0_u8; 39];
    first_tunnel
        .read_exact(&mut established)
        .await
        .expect("the established line arrives");
    assert_eq!(
        std::str::from_utf8(&established).expect("ascii"),
        "HTTP/1.1 200 Connection established\r\n\r\n"
    );

    let head = exchange(&proxy, &connect_request(&format!("127.0.0.1:{port}"))).await;

    assert!(
        head.starts_with("HTTP/1.1 503 Service Unavailable"),
        "got {head:?}"
    );
    assert!(head.contains("X-Kata-Egress-Refused: concurrency_cap"));
    never_accepts(
        &listener,
        "the cap is reached, so nothing else is connected",
    )
    .await;
    assert_eq!(labels(&proxy).await, vec!["concurrency_cap"]);
    assert_eq!(proxy.opened_tunnels(), 1);
    drop(accepted);
    drop(first_tunnel);
}

/// **The per-connection byte budget tears its own tunnel down and records itself.**
///
/// The budget is counted in BOTH directions, so this cell spends it from the upstream
/// side — the direction a model response arrives on.
#[tokio::test]
async fn the_per_connection_byte_budget_tears_the_tunnel_down() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.per_connection_bytes = 8;
    let proxy = proxy_for(port, budgets).await;

    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .await
        .expect("writable");
    let (mut server, _) = listener.accept().await.expect("connected");
    let mut established = [0_u8; 39];
    client.read_exact(&mut established).await.expect("200");

    server
        .write_all(&[0xAB_u8; 64])
        .await
        .expect("the upstream can push");

    // The client's socket reaching EOF is the teardown, read off the socket.
    let mut drained = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut drained))
        .await
        .expect("the tunnel ends inside the window")
        .expect("and ends by EOF, not by error");

    assert!(
        drained.len() <= 64,
        "the relay must not invent bytes; got {}",
        drained.len()
    );
    assert_eq!(labels(&proxy).await, vec!["connection_byte_budget"]);
    assert!(
        proxy.relayed_bytes() >= 8,
        "the budget is reached by bytes that MOVED; counted {}",
        proxy.relayed_bytes()
    );
}

/// **The attempt's total budget, once spent, refuses the NEXT tunnel before the
/// upstream sees it — and admitted the first one.**
#[tokio::test]
async fn the_total_budget_admits_the_first_tunnel() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.total_bytes = 8;
    let proxy = proxy_for(port, budgets).await;

    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .await
        .expect("writable");
    let (mut server, _) = listener.accept().await.expect("the FIRST tunnel connects");
    let mut established = [0_u8; 39];
    client.read_exact(&mut established).await.expect("200");
    client
        .write_all(b"0123456789abcdef")
        .await
        .expect("the client can push");
    let mut seen = [0_u8; 16];
    tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut seen))
        .await
        .expect("the bytes arrive upstream")
        .expect("in full");
    assert_eq!(
        &seen, b"0123456789abcdef",
        "relayed opaquely, byte for byte"
    );
    let mut drained = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut drained))
        .await
        .expect("the spent tunnel ends")
        .expect("by EOF");

    // The SECOND tunnel: refused, and the upstream never sees it.
    let head = exchange(&proxy, &connect_request(&format!("127.0.0.1:{port}"))).await;
    assert!(
        head.starts_with("HTTP/1.1 503 Service Unavailable"),
        "got {head:?}"
    );
    assert!(head.contains("X-Kata-Egress-Refused: total_byte_budget"));
    never_accepts(&listener, "the attempt's total egress budget is spent").await;
    assert_eq!(
        labels(&proxy).await,
        vec!["total_byte_budget", "total_byte_budget"],
        "once when the first tunnel crossed it, once when the second was refused for it"
    );
    assert_eq!(proxy.opened_tunnels(), 1);
}

/// **A tunnel that relays nothing for the idle window is torn down and recorded.**
#[tokio::test]
async fn an_idle_tunnel_is_torn_down() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.idle = Duration::from_millis(80);
    let proxy = proxy_for(port, budgets).await;

    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .await
        .expect("writable");
    let (server, _) = listener.accept().await.expect("connected");
    let mut established = [0_u8; 39];
    client.read_exact(&mut established).await.expect("200");

    // Neither side writes. The window expires, and the client's EOF is the proof.
    let mut drained = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut drained))
        .await
        .expect("the idle tunnel ends inside the window")
        .expect("by EOF");
    assert!(drained.is_empty(), "an idle tunnel relayed nothing");
    assert_eq!(labels(&proxy).await, vec!["idle_timeout"]);
    drop(server);
}

// ---------------------------------------------------------------------------
// The POSITIVE cell, and teardown
// ---------------------------------------------------------------------------

/// **An allowed authority relays bytes BOTH WAYS, opaquely.**
///
/// The payload is chosen so a proxy that parsed or rewrote anything after the
/// `CONNECT` would be caught: it is not valid HTTP in either direction.
#[tokio::test]
async fn a_tunnel_relays_bytes_both_ways() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .await
        .expect("writable");
    let (mut server, _) = listener
        .accept()
        .await
        .expect("the allowed upstream connects");
    let mut established = [0_u8; 39];
    client.read_exact(&mut established).await.expect("200");

    // Client -> upstream. A TLS ClientHello's first bytes, which is what really
    // crosses here, and which no HTTP parser would let through unchanged.
    let up = [0x16_u8, 0x03, 0x01, 0x00, 0xFF, 0x01, 0x00, 0x00];
    client.write_all(&up).await.expect("the client pushes");
    let mut seen_up = [0_u8; 8];
    tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut seen_up))
        .await
        .expect("arrives")
        .expect("in full");
    assert_eq!(seen_up, up, "relayed byte for byte, not interpreted");

    // Upstream -> client.
    let down = [0x16_u8, 0x03, 0x03, 0x00, 0x2A, 0x02, 0x00, 0x00, 0x26];
    server.write_all(&down).await.expect("the upstream pushes");
    let mut seen_down = [0_u8; 9];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut seen_down))
        .await
        .expect("arrives")
        .expect("in full");
    assert_eq!(seen_down, down, "and back the other way unchanged");

    assert!(proxy.refusals().await.is_empty(), "nothing was refused");
    assert_eq!(proxy.opened_tunnels(), 1);
    assert_eq!(
        proxy.relayed_bytes(),
        17,
        "8 up + 9 down, counted once each"
    );
    assert_eq!(
        proxy.allowed_authorities().await,
        BTreeSet::from([format!("127.0.0.1:{port}")]),
        "the CONNECT-host evidence names exactly the authority the tunnel opened for"
    );
}

/// **`close` tears a LIVE tunnel down, closes the listener, and reports
/// `Confirmed { EgressTunnelRegistry }`.**
///
/// The teardown is read off the CLIENT's socket (EOF) and off the NETWORK (the
/// listener's address refuses new connections once the fd is gone) before the
/// reported outcome is looked at, so the cell does not ask the proxy whether the
/// proxy tore anything down.
#[tokio::test]
async fn teardown_closes_a_live_tunnel() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;
    let proxy_addr = proxy.local_addr();

    let mut client = TcpStream::connect(proxy_addr)
        .await
        .expect("the proxy accepts");
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .await
        .expect("writable");
    let (server, _) = listener.accept().await.expect("connected");
    let mut established = [0_u8; 39];
    client.read_exact(&mut established).await.expect("200");
    assert_eq!(proxy.live_tunnels(), 1);

    let outcome = proxy.close().await;

    let mut drained = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut drained))
        .await
        .expect("a closed proxy ends every tunnel it accepted")
        .expect("by EOF");
    // The accept task's abort lands when the runtime cancels it, not when `close`
    // schedules it — so poll the refusal rather than asserting the first connect.
    let refused = tokio::time::timeout(Duration::from_secs(5), async {
        while TcpStream::connect(proxy_addr).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        refused.is_ok(),
        "the listener fd is attempt state and an ended attempt accepts on none"
    );
    match outcome {
        TeardownOutcome::Confirmed { probe, .. } => assert_eq!(
            probe,
            TeardownProbe::EgressTunnelRegistry,
            "the outcome must name the observation that answered"
        ),
        other @ TeardownOutcome::Ambiguous { .. } => {
            panic!("a drained registry is Confirmed, not {other:?}")
        }
    }
    drop(server);
}

// ---------------------------------------------------------------------------
// Construction-time refusals
// ---------------------------------------------------------------------------

/// **Every clause of `EgressAllowlist::exact`'s refused set refuses.**
#[test]
fn the_allowlist_refuses_what_it_claims_to() {
    for (entries, why) in [
        (vec![], "an empty allowlist is not an egress bound"),
        (vec![("", 443_u16)], "an empty host"),
        (
            vec![("*.example.com", 443)],
            "a wildcard is not implemented",
        ),
        (vec![("a?.example.com", 443)], "nor any other pattern"),
        (
            vec![("example.com:443", 443)],
            "a host that is already an authority",
        ),
        (
            vec![("exämple.com", 443)],
            "a non-ASCII host has two spellings",
        ),
        (vec![("example.com", 0)], "port 0"),
        // The CHARSET, which a `*`/`?`/`/` screen alone would admit every one of:
        (vec![("example.com\n", 443)], "a trailing newline"),
        (vec![("example.com 443", 443)], "an embedded space"),
        (vec![("example.com/", 443)], "a path separator"),
        (vec![("example.com%2f", 443)], "a percent escape"),
        (
            vec![("exa_mple.com", 443)],
            "an underscore is not a hostname character",
        ),
        (vec![("-example.com", 443)], "a label beginning with `-`"),
        (vec![("example-.com", 443)], "a label ending with `-`"),
        (vec![("example..com", 443)], "an empty label"),
        (vec![(".example.com", 443)], "a leading dot"),
        (vec![("example.com.", 443)], "a trailing dot"),
        (
            vec![("::1", 443)],
            "an UNBRACKETED IPv6 literal, which the request parser would split",
        ),
        (vec![("[::1", 443)], "a bracket that does not close"),
        (
            vec![("[not-an-address]", 443)],
            "brackets around something that is not IPv6",
        ),
    ] {
        assert!(
            EgressAllowlist::exact(entries).is_err(),
            "this input is in the allowlist's refused set: {why}"
        );
    }
    assert!(
        EgressAllowlist::exact([(&"a".repeat(254)[..], 443_u16)]).is_err(),
        "a host past the 253-byte domain-name limit is in the refused set"
    );
    // And the PERMITTED forms are admitted, so the charset is a bound and not a wall.
    for permitted in [
        "api.example.com",
        "127.0.0.1",
        "[::1]",
        "a",
        "xn--80ak6aa92e.com",
    ] {
        EgressAllowlist::exact([(permitted, 443_u16)])
            .unwrap_or_else(|error| panic!("{permitted} is a hostname or IP literal: {error}"));
    }
    let ok = EgressAllowlist::exact([("API.Example.COM", 443_u16)]).expect("a valid pair");
    assert!(
        ok.allows("api.example.com", 443),
        "DNS is case-insensitive, so the allowlist must be too"
    );
    assert!(!ok.allows("api.example.com", 8443), "and the port is exact");
    assert!(ok.knows_host("api.example.com"));
    assert!(!ok.knows_host("other.example.com"));
    assert_eq!(
        ok.entries().len(),
        1,
        "the entries accessor returns the set that was built, not an empty one"
    );
    assert!(
        ok.entries().iter().next().expect("one entry").host() == "api.example.com",
        "lowercased at admission, sorted in the set"
    );
}

/// **`EgressProxy::accept_on`'s refused set refuses, each clause named.**
#[tokio::test]
async fn accept_on_refuses_what_it_claims_to() {
    let allow = || EgressAllowlist::exact([("example.com", 443_u16)]).expect("a pair");
    let cases: Vec<(EgressBudgets, &str)> = vec![
        (
            EgressBudgets {
                max_concurrent: 0,
                ..wide()
            },
            "a proxy that can hold no tunnel",
        ),
        (
            EgressBudgets {
                max_pending: 0,
                ..wide()
            },
            "a proxy that can read no connection",
        ),
        (
            EgressBudgets {
                per_connection_bytes: 0,
                ..wide()
            },
            "a tunnel that may relay no bytes",
        ),
        (
            EgressBudgets {
                total_bytes: 0,
                ..wide()
            },
            "an attempt that may relay no bytes",
        ),
        (
            EgressBudgets {
                idle: Duration::ZERO,
                ..wide()
            },
            "an idle window every tunnel expires in",
        ),
        (
            EgressBudgets {
                max_request_line_bytes: 8,
                ..wide()
            },
            "a request-line cap no valid request fits",
        ),
        (
            EgressBudgets {
                max_header_block_bytes: 1,
                ..wide()
            },
            "a header cap the bare terminator does not fit",
        ),
    ];
    for (budgets, why) in cases {
        let (listener, _) = upstream().await;
        assert!(
            EgressProxy::accept_on(listener, allow(), budgets).is_err(),
            "this input is in accept_on's refused set: {why}"
        );
    }
    // And the floor itself is ADMITTED: `CONNECT h:1 HTTP/1.1\r\n` is 24 bytes and
    // the bare terminator is 2, so those exact caps are the smallest legal bound —
    // a check that refused them would refuse the request shape it claims to admit.
    for (field, value) in [("request_line", 24_usize), ("header_block", 2_usize)] {
        let mut budgets = wide();
        match field {
            "request_line" => budgets.max_request_line_bytes = value,
            _ => budgets.max_header_block_bytes = value,
        }
        let (listener, _) = upstream().await;
        assert!(
            EgressProxy::accept_on(listener, allow(), budgets).is_ok(),
            "the smallest cap a valid request fits ({field}={value}) is admitted, not refused"
        );
    }
}

/// **Two receivers cannot share one attempt's handoff socket path.**
///
/// `Receiver::bind` is where one attempt could take over another's egress
/// plumbing: the handoff socket names the attempt the hook's fd belongs to, and a
/// second bind that unlinked the first's socket would pass the WRONG attempt's
/// listener to whoever connected next. The refusal is a containment property —
/// and a socket file that survives its receiver stays occupied, because nothing
/// may unlink a path it did not create.
#[tokio::test]
async fn a_second_handoff_bind_on_the_same_path_is_refused() {
    let root = tempfile::tempdir().expect("a temp attempt root");
    let path = root.path().join("egress").join("handoff.sock");
    let expected = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 19200);
    let first = Receiver::bind(&path, expected).expect("the first binds");
    assert!(
        Receiver::bind(&path, expected).is_err(),
        "the socket path is already occupied by an attempt that has not ended"
    );
    drop(first);
    assert!(
        Receiver::bind(&path, expected).is_err(),
        "a dropped receiver's socket file stays occupied rather than be taken over"
    );
}

/// **The handoff socket lives beside the bound roots, never inside one.**
///
/// The path shape is the drive's (`<attempt>/egress/handoff.sock`); the cell binds
/// a receiver at it and reads the position off the FILESYSTEM: the socket's parent
/// is not `work/`, `out/` or `io/` — a socket under a bound root would be an
/// egress path a stage could reach by filesystem position, which is the allowlist
/// bypassed.
#[tokio::test]
async fn the_handoff_socket_is_outside_every_bound_root() {
    let root = tempfile::tempdir().expect("a temp attempt root");
    let path = root.path().join("egress").join("handoff.sock");
    let expected = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 19200);
    let _receiver = Receiver::bind(&path, expected).expect("binds, creating egress/");
    assert!(path.exists(), "the receiver created the socket file");
    for bound in ["work", "out", "io", "tmp"] {
        assert!(
            !path.starts_with(root.path().join(bound)),
            "a socket inside {bound}/ would be an egress path a stage could reach by filesystem \
             position, which is the allowlist bypassed"
        );
    }
    assert_eq!(
        path.parent().expect("a parent"),
        root.path().join("egress"),
        "and it is the attempt's own egress directory, not a host temp path"
    );
}

/// A bound receiver on a temp root, for the `receive` cells: `expected` is the
/// endpoint the descriptor must claim. `name` differs per call because a dropped
/// receiver's socket file stays occupied — nothing unlinks a path it did not
/// create (`a_second_handoff_bind_on_the_same_path_is_refused` pins that).
fn receiver(
    root: &std::path::Path,
    name: &str,
    expected: std::net::SocketAddrV4,
) -> (Receiver, std::path::PathBuf) {
    let path = root.join("egress").join(name);
    let receiver = Receiver::bind(&path, expected).expect("the receiver binds");
    (receiver, path)
}

/// **A hook that never arrives refuses as `TimedOut` — the arm that names
/// `egress_listener_unavailable` at the drive.**
///
/// A createContainer hook runs only while the runtime's create is mid-flight, and
/// it exits successfully only on the ack, so a receive that never heard from one
/// is a create that cannot complete: this side never sent that ack.
/// `ProvenNotPerformed` is honest BECAUSE the wait is bidirectional.
///
/// The reason claims only what the worker observed. A hook that failed its
/// connect has EXITED (w6-fu5's mutation (A): `connect_through_parent`
/// connecting the long path directly), and this side cannot tell that hook from
/// one still waiting — so the text says the ack was never sent, never that the
/// hook is waiting.
///
/// **Would red if:** the reason claimed the hook is still waiting on the ack.
#[tokio::test]
async fn a_handoff_that_never_arrives_is_timed_out() {
    let root = tempfile::tempdir().expect("a temp attempt root");
    let expected = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 19200);
    let (receiver, _path) = receiver(root.path(), "handoff.sock", expected);

    let refusal = receiver
        .receive_within(Duration::from_millis(150))
        .await
        .err()
        .expect("no hook ever connected");

    assert!(
        matches!(refusal, HandoffRefusal::TimedOut { .. }),
        "the timeout arm, named for what was observed: {refusal}"
    );
    let reason = refusal.to_string();
    assert!(
        reason.contains("within 150ms")
            && reason.contains("never sent the ack")
            && reason.contains("the create cannot have completed"),
        "the reason names the observation and what follows from it: {reason}"
    );
    assert!(
        !reason.contains("still waiting"),
        "the worker does not observe the hook, so it does not claim it waits: {reason}"
    );
}

/// **A peer that is not the hook — wrong marker, wrong fd count, a listener for a
/// different endpoint, or an early close — is refused by the arm that names it.**
///
/// Each arm is cheap to reach: the message is one byte plus ancillary data, so a
/// foreign peer's shape is a refusal, never a half-adopted descriptor. What is NOT
/// exercised is the happy path — that needs a real netns to bind a real listener
/// in, and is the live cells' job.
#[tokio::test]
async fn a_peer_that_is_not_the_hook_is_refused_by_the_arm_that_names_it() {
    let root = tempfile::tempdir().expect("a temp attempt root");
    let expected = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 19200);

    // PeerEnded: connect, close, no byte.
    {
        let (receiver, path) = receiver(root.path(), "peer-ended.sock", expected);
        let peer = kata_transport::unix_socket::connect_tokio(&path)
            .await
            .expect("connects");
        drop(peer);
        let refusal = receiver
            .receive()
            .await
            .err()
            .expect("a peer that closes empty is not a handoff");
        assert!(
            matches!(refusal, HandoffRefusal::PeerEnded),
            "got {refusal}"
        );
    }
    // WrongMarker: one byte, not `b'F'`.
    {
        let (receiver, path) = receiver(root.path(), "wrong-marker.sock", expected);
        let peer = kata_transport::unix_socket::connect_std(&path).expect("connects");
        std::io::Write::write_all(&mut &peer, b"X").expect("one byte");
        let refusal = receiver
            .receive()
            .await
            .err()
            .expect("a wrong marker is not the handshake");
        assert!(
            matches!(refusal, HandoffRefusal::WrongMarker { got: b'X' }),
            "got {refusal}"
        );
        drop(peer);
    }
    // WrongDescriptorCount: the marker, but no SCM_RIGHTS.
    {
        let (receiver, path) = receiver(root.path(), "no-descriptor.sock", expected);
        let peer = kata_transport::unix_socket::connect_std(&path).expect("connects");
        std::io::Write::write_all(&mut &peer, b"F").expect("the marker byte");
        let refusal = receiver
            .receive()
            .await
            .err()
            .expect("a marker with no descriptor is not a handoff");
        assert!(
            matches!(refusal, HandoffRefusal::WrongDescriptorCount { count: 0 }),
            "got {refusal}"
        );
        drop(peer);
    }
    // WrongEndpoint: a real listener fd, bound to the WRONG port — sent with a
    // real SCM_RIGHTS message so only the getsockname check can catch it.
    {
        let (receiver, path) = receiver(root.path(), "wrong-endpoint.sock", expected);
        let stray = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a stray listener");
        let stray_port = stray.local_addr().expect("its own port").port();
        assert_ne!(stray_port, expected.port(), "the trap must differ");
        let peer = kata_transport::unix_socket::connect_std(&path).expect("connects");
        use std::os::fd::AsFd as _;
        let mut space = vec![std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut space);
        let descriptors = [stray.as_fd()];
        assert!(
            ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(&descriptors)),
            "one descriptor fits the buffer"
        );
        rustix::net::sendmsg(
            &peer,
            &[std::io::IoSlice::new(b"F")],
            &mut ancillary,
            rustix::net::SendFlags::empty(),
        )
        .expect("the stray descriptor travels");
        let refusal = receiver
            .receive()
            .await
            .err()
            .expect("a listener for the wrong endpoint is not this handoff's fd");
        assert!(
            matches!(refusal, HandoffRefusal::WrongEndpoint { .. }),
            "got {refusal}"
        );
        drop(peer);
        drop(stray);
    }
}

/// **`EgressPlumbing` produces exactly eight variables: the proxy URL under
/// `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` in both casings, and the loopback
/// bypass under `NO_PROXY` in both, in that order.**
///
/// The `unix:` form is not refused here because it is UNREPRESENTABLE: the only
/// constructor takes a port. See `kata_worker::egress_proxy`'s module doc for the
/// measurement — undici refuses `unix:` outright and reqwest IGNORES it and goes
/// direct, which is a fail-open egress bypass.
#[test]
fn the_plumbing_renders_a_loopback_endpoint() {
    let plumbing = EgressPlumbing::loopback("/attempt/egress/proxy.sock".into(), 18080)
        .expect("an absolute socket path and a non-zero port");
    assert_eq!(plumbing.guest_proxy_url(), "http://127.0.0.1:18080");
    assert_eq!(
        plumbing.guest_env(),
        vec![
            "HTTP_PROXY=http://127.0.0.1:18080".to_owned(),
            "HTTPS_PROXY=http://127.0.0.1:18080".to_owned(),
            "http_proxy=http://127.0.0.1:18080".to_owned(),
            "https_proxy=http://127.0.0.1:18080".to_owned(),
            "ALL_PROXY=http://127.0.0.1:18080".to_owned(),
            "all_proxy=http://127.0.0.1:18080".to_owned(),
            "NO_PROXY=localhost,127.0.0.1,[::1]".to_owned(),
            "no_proxy=localhost,127.0.0.1,[::1]".to_owned(),
        ],
        "the proxy pair, its lowercase spellings (curl reads only `http_proxy` for an http URL) and `ALL_PROXY` in both, then the loopback bypass — a vendor's OWN localhost calls (opencode's directory SDK, measured) must never be CONNECTed through a proxy that refuses loopback targets"
    );
    assert!(
        EgressPlumbing::loopback("/attempt/egress/proxy.sock".into(), 0).is_err(),
        "port 0 is unconnectable"
    );
    assert!(
        EgressPlumbing::loopback("attempt/egress/proxy.sock".into(), 8080).is_err(),
        "a relative path in a durable plan resolves against the reader's cwd"
    );
}

/// **`close` also ends a connection that was accepted but never finished a request.**
///
/// Such a connection is NOT in the tunnel registry — it never reached
/// `200 Connection established` — so a `close` that only watched the registry would
/// report `Confirmed` with a socket still open. That is the false-`Confirmed` shape
/// the kata-owned teardown exists to close, in its egress form.
#[tokio::test]
async fn teardown_closes_a_connection_still_parsing() {
    let (listener, _) = upstream().await;
    let proxy = EgressProxy::accept_on(
        listener,
        EgressAllowlist::exact([("example.com", 443_u16)]).expect("a pair"),
        wide(),
    )
    .expect("accepts on its listener");

    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    // A request line with no terminator: the proxy is parked in the parser, and the
    // idle window (10s here) is far longer than this cell's own patience.
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1")
        .await
        .expect("writable");
    // The connection must actually be ACCEPTED and parked in the parser before
    // `close` is called, or the cell proves only that dropping a listener closes a
    // backlog — which it did, silently, until this wait was added.
    let accepted = tokio::time::timeout(Duration::from_secs(5), async {
        while proxy.accepted_connections() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(accepted.is_ok(), "the proxy must accept the connection");
    assert_eq!(proxy.live_tunnels(), 0, "no tunnel was ever established");

    let outcome = proxy.close().await;

    // EOF *or* `ECONNRESET`, and both are the connection ending: the client's unread
    // request-line remainder is still queued, and a `SOCK_STREAM` socket closed with
    // input pending is RESET by the kernel. There is nothing to deliver to a torn-down
    // connection, so unlike a refusal this path does not drain first. What the cell
    // refuses is the third answer — the read BLOCKING, i.e. a socket still open.
    let mut drained = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut drained))
        .await
        .expect("a closed proxy ends a connection it accepted, parsed or not");
    if let Err(error) = ended {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset,
            "the only non-EOF ending a closed socket with queued input may have is a reset"
        );
    }
    assert!(
        outcome.is_confirmed(),
        "and reports the registry it drained: {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// The resource/teardown bounds on the boundary
// ---------------------------------------------------------------------------

/// Open a tunnel and hand back the client half, the upstream half and the proxy.
///
/// Every cell below needs the same five steps, and a cell that inlined them would be
/// asserting on a tunnel it had not established.
async fn open_tunnel(
    proxy: &EgressProxy,
    listener: &TcpListener,
    port: u16,
) -> (TcpStream, TcpStream) {
    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client
        .write_all(connect_request(&format!("127.0.0.1:{port}")).as_bytes())
        .await
        .expect("writable");
    let (server, _) = listener.accept().await.expect("the upstream connects");
    let mut established = [0_u8; 39];
    client
        .read_exact(&mut established)
        .await
        .expect("the established line arrives");
    (client, server)
}

/// **MUST-FIX 1a: a tunnel whose client has STOPPED READING is still torn down by
/// `close`, and the teardown is `Confirmed`.**
///
/// # The defect this reproduces
///
/// The relay's `select!` covered only the two reads. A client that opened a tunnel and
/// then stopped reading filled the socket buffer, parked the task inside
/// `client.write_all`, and reached no select arm — so the close SIGNAL was never
/// observed, `close` reported `Ambiguous { StillPresentAtDeadline }`, and the upstream
/// TCP connection outlived the attempt. An egress path surviving the authorization that
/// granted it is the whole thing this component exists to prevent.
///
/// # What it scores, and the two mechanisms it does NOT separate
///
/// Either of two independent fixes makes this green, MEASURED one at a time: the close
/// arm inside the bounded write, and `close`'s `abort_all`. With only the abort (close
/// arm removed) it passes; with only the close arm it passes; with NEITHER — the
/// pre-fix relay write and no abort — it fails in 2s with
/// `Ambiguous { StillPresentAtDeadline }`. So this cell is a bound on the OUTCOME, not
/// a proof of which mechanism delivered it, and it is written that way on purpose: a
/// cell pinned to one of them would go green while the other silently carried the
/// property.
///
/// It also depends on the live count being held by a drop guard: an aborted task runs no
/// further statement, so a hand-written `fetch_sub` would never run and the slot would
/// leak permanently.
///
/// The idle window is LONG here on purpose: this cell must score the abort, not the
/// idle timeout, so the tunnel has to still be parked when `close` is called.
#[tokio::test]
async fn close_tears_down_a_tunnel_parked_writing_to_a_client_that_stopped_reading() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.idle = Duration::from_secs(30);
    budgets.per_connection_bytes = 1 << 30;
    budgets.total_bytes = 1 << 30;
    let proxy = proxy_for(port, budgets).await;

    let (client, mut server) = open_tunnel(&proxy, &listener, port).await;

    // FLOOD from upstream while the client reads nothing. Past both socket buffers the
    // proxy's `write_all` to the client blocks, which is the parked state.
    let flood = tokio::spawn(async move {
        let block = vec![0xCD_u8; 64 * 1024];
        loop {
            if server.write_all(&block).await.is_err() {
                return;
            }
        }
    });
    // Wait until bytes have actually been relayed, so the tunnel is provably inside the
    // relay and not still parsing.
    let pumped = tokio::time::timeout(Duration::from_secs(5), async {
        while proxy.relayed_bytes() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(pumped.is_ok(), "the relay must move bytes before the close");
    assert_eq!(
        proxy.live_tunnels(),
        1,
        "the tunnel is open and the client is not reading"
    );

    let outcome = tokio::time::timeout(Duration::from_secs(10), proxy.close())
        .await
        .expect("close is bounded and must not hang");

    assert!(
        outcome.is_confirmed(),
        "a parked tunnel must be ABORTED and its slot released, not waited out: {outcome:?}"
    );
    match outcome {
        TeardownOutcome::Confirmed { probe, .. } => {
            assert_eq!(probe, TeardownProbe::EgressTunnelRegistry);
        }
        other @ TeardownOutcome::Ambiguous { .. } => panic!("{other:?}"),
    }
    // The client's socket ends, read off the socket rather than off the proxy.
    let mut client = client;
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
        .await
        .expect("the client's tunnel ends");
    if let Err(error) = ended {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    flood.abort();
}

/// **MUST-FIX 1b: a client that stops reading for the whole idle window is torn down by
/// the PROXY, with an `idle_timeout` recorded — no `close` required.**
///
/// The companion to the cell above: 1a scores the abort, this scores the bound that
/// means an abort is rarely needed. A blocked `write_all` is an idle tunnel, and before
/// the fix it was the one flavour of idle the idle window did not cover.
#[tokio::test]
async fn a_client_that_stops_reading_is_torn_down_by_the_idle_window() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.idle = Duration::from_millis(200);
    // The flood reaches `wide()`'s byte budgets in writes, not in time — widen them
    // so the IDLE window is the bound this cell scores.
    budgets.per_connection_bytes = 1 << 30;
    budgets.total_bytes = 1 << 30;
    let proxy = proxy_for(port, budgets).await;

    let (client, mut server) = open_tunnel(&proxy, &listener, port).await;

    let flood = tokio::spawn(async move {
        let block = vec![0xCD_u8; 64 * 1024];
        loop {
            if server.write_all(&block).await.is_err() {
                return;
            }
        }
    });
    // The tunnel must END without anyone closing the proxy, and the registry must drain.
    let drained = tokio::time::timeout(Duration::from_secs(10), async {
        while proxy.live_tunnels() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "a write blocked for the whole idle window must end the tunnel; it stayed live"
    );
    assert!(
        labels(&proxy).await.contains(&"idle_timeout"),
        "and it must be recorded as the idle tunnel it is: {:?}",
        labels(&proxy).await
    );
    flood.abort();
    drop(client);
    let _ = proxy.close().await;
}

/// **MUST-FIX 2a: a connection that never finishes a request is TIME-bounded, as a typed
/// refusal.**
///
/// Every other bound on the parse is a size bound, and a client trickling a well-formed
/// request stays inside all of them indefinitely — measured before the fix as a read
/// that never returned after six idle windows.
#[tokio::test]
async fn a_request_that_never_finishes_is_timed_out() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.idle = Duration::from_millis(150);
    let proxy = proxy_for(port, budgets).await;

    let head = tokio::time::timeout(Duration::from_secs(5), exchange(&proxy, "CONNECT 1"))
        .await
        .expect("the parse must be bounded in TIME, not only in size");

    assert!(
        head.starts_with("HTTP/1.1 408 Request Timeout"),
        "got {head:?}"
    );
    assert!(head.contains("X-Kata-Egress-Refused: request_timeout"));
    never_accepts(&listener, "no authority was ever parsed").await;
    assert_eq!(labels(&proxy).await, vec!["request_timeout"]);
}

/// **MUST-FIX 2b: accepted-but-unparsed connections are CAPPED.**
///
/// `max_concurrent` only applies after the parse, so before `max_pending` existed N
/// clients sending `CONNECT 1` and stalling held N tasks and N descriptors against a
/// limit that had not started counting.
#[tokio::test]
async fn pending_connections_are_capped_before_the_parse() {
    let (listener, port) = upstream().await;
    let mut budgets = wide();
    budgets.max_pending = 1;
    // Long, so the cap and not the request timeout is what refuses the second client.
    budgets.idle = Duration::from_secs(30);
    let proxy = proxy_for(port, budgets).await;

    let mut stalled = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    stalled
        .write_all(b"CONNECT 1")
        .await
        .expect("a partial request line");
    let slot_taken = tokio::time::timeout(Duration::from_secs(5), async {
        while proxy.pending_connections() != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        slot_taken.is_ok(),
        "the first connection must hold the slot"
    );

    let head = exchange(&proxy, &connect_request(&format!("127.0.0.1:{port}"))).await;

    assert!(
        head.starts_with("HTTP/1.1 503 Service Unavailable"),
        "got {head:?}"
    );
    assert!(head.contains("X-Kata-Egress-Refused: pending_cap"));
    never_accepts(&listener, "the pending cap is reached before any parse").await;
    assert_eq!(labels(&proxy).await, vec!["pending_cap"]);
    assert_eq!(
        proxy.live_tunnels(),
        0,
        "a pending connection is not a tunnel and must not be counted as one"
    );
    drop(stalled);
    let _ = proxy.close().await;
}

/// **MUST-FIX 3: a client that TRICKLES after a refusal is closed by one overall
/// deadline, not one per read.**
///
/// The drain window was per-`read`, so every byte reset it: at one byte per interval a
/// refused connection, its task and its descriptor stayed alive for the whole byte cap —
/// about 100 minutes at the defaults. The byte cap remains as a second, independent
/// bound; this cell scores the time one.
#[tokio::test]
async fn a_trickling_refused_client_is_closed_by_the_drain_deadline() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    // A refused request (not CONNECT), then a trickle that would keep a per-read window
    // open forever.
    client
        .write_all(format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .expect("writable");
    let trickle = tokio::spawn(async move {
        loop {
            if client.write_all(b"x").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    // The connection must be ACCEPTED first, or the wait below observes a `0` that only
    // means the accept loop has not run yet — which is how this cell first passed
    // against the unfixed code.
    let accepted = tokio::time::timeout(Duration::from_secs(5), async {
        while proxy.accepted_connections() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(accepted.is_ok(), "the proxy must accept the connection");

    // Then it must be GONE — nothing pending — well inside the per-read window times the
    // byte cap. Two seconds is ~8x the one overall deadline and ~1/3000th of what the
    // per-read window allowed.
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        while proxy.pending_connections() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "a trickling refused client must be closed by ONE deadline over the whole \
         answer-and-drain; it was still held"
    );
    assert_eq!(labels(&proxy).await, vec!["method_not_connect"]);
    never_accepts(&listener, "a refused request reaches no upstream").await;
    trickle.abort();
    let _ = proxy.close().await;
}

/// **MUST-FIX 4a: a client that hangs up mid-request is NOT recorded as a refusal.**
///
/// `read_line` collapsed the cap, EOF and invalid UTF-8 into one `None`, so a peer that
/// closed after `CONN` was answered `414 request_line_too_long` — a refusal kata never
/// made, attributed to a size bound nobody crossed. The event is counted instead, so the
/// absence of a refusal can be asserted against the presence of the event.
#[tokio::test]
async fn a_client_that_hangs_up_mid_request_is_not_a_refusal() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;
    assert_eq!(
        proxy.hung_up_connections(),
        0,
        "a proxy that has seen no connection hang up has counted none"
    );

    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client.write_all(b"CONN").await.expect("a partial method");
    client
        .shutdown()
        .await
        .expect("and then the client hangs up");

    let counted = tokio::time::timeout(Duration::from_secs(5), async {
        while proxy.hung_up_connections() != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(counted.is_ok(), "the hang-up must be observable");
    assert!(
        proxy.refusals().await.is_empty(),
        "kata refused NOTHING here: {:?}",
        labels(&proxy).await
    );
    never_accepts(&listener, "nothing was ever parsed").await;
    drop(client);
    let _ = proxy.close().await;
}

/// **MUST-FIX 4b: a request line that is not UTF-8 is a 400, and a non-UTF-8 HEADER is
/// its own 400.**
///
/// Both were `None` from `read_line` and therefore `414`/`431` — size refusals for a
/// character-set problem. The header arm is separate from the request-line arm because
/// an operator reading `malformed_request_line` for a bad header would look at the wrong
/// bytes.
#[tokio::test]
async fn a_request_that_is_not_utf8_is_a_400() {
    let (listener, port) = upstream().await;

    // The request LINE.
    let line_proxy = proxy_for(port, wide()).await;
    let mut client = TcpStream::connect(line_proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client
        .write_all(b"CONNECT \xFF\xFE:443 HTTP/1.1\r\n\r\n")
        .await
        .expect("writable");
    let mut head = Vec::new();
    client.read_to_end(&mut head).await.expect("answered");
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 400 Bad Request"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: malformed_request_line"));
    assert_eq!(labels(&line_proxy).await, vec!["malformed_request_line"]);
    never_accepts(
        &listener,
        "a request line that is not text parses to no authority",
    )
    .await;
    let _ = line_proxy.close().await;

    // A HEADER line.
    let header_proxy = proxy_for(port, wide()).await;
    let mut client = TcpStream::connect(header_proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client
        .write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n").as_bytes())
        .await
        .expect("writable");
    client
        .write_all(b"X-Bad: \xFF\xFE\r\n\r\n")
        .await
        .expect("writable");
    let mut head = Vec::new();
    client.read_to_end(&mut head).await.expect("answered");
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 400 Bad Request"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: malformed_header_line"));
    assert_eq!(labels(&header_proxy).await, vec!["malformed_header_line"]);
    never_accepts(&listener, "a header that is not text stops the request").await;
    let _ = header_proxy.close().await;
}

/// **A port spelling Rust's integer parser accepts is REFUSED, because the allowlist
/// matches one spelling.**
///
/// `u16::from_str` yields 443 for `443`, `+443` and `0443` alike. An allowlist keyed on
/// exact pairs whose parser normalizes three spellings into one would log, refuse and
/// meter the spelling KATA chose rather than the one the client sent — and every future
/// comparison against the raw target (a wildcard match, a per-authority budget) would be
/// comparing against a string no client sent.
#[tokio::test]
async fn a_non_canonical_port_spelling_is_refused() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    // The third spelling is refused a step EARLIER, and the pair says which: a space
    // inside the target makes the request line four tokens, so it never reaches the
    // authority parser. Asserting `malformed_authority` for it would have been a cell
    // claiming a mechanism the other one performed.
    let spellings = [
        (format!("+{port}"), "malformed_authority"),
        (format!("0{port}"), "malformed_authority"),
        (format!(" {port}"), "malformed_request_line"),
    ];
    for (spelling, expected) in &spellings {
        let head = exchange(&proxy, &connect_request(&format!("127.0.0.1:{spelling}"))).await;
        assert!(
            head.starts_with("HTTP/1.1 400 Bad Request"),
            "`{spelling}` must not be normalized into the allowlisted port; got {head:?}"
        );
        assert!(
            head.contains(&format!("X-Kata-Egress-Refused: {expected}")),
            "`{spelling}` must be refused as {expected}; got {head:?}"
        );
    }
    never_accepts(
        &listener,
        "a non-canonical spelling of an allowlisted port reaches nothing",
    )
    .await;
    assert_eq!(
        labels(&proxy).await,
        spellings
            .iter()
            .map(|(_, expected)| *expected)
            .collect::<Vec<_>>()
    );
    let _ = proxy.close().await;
}

/// **A dropped proxy releases its listener, so a retry of the same attempt is not
/// refused for the previous try's lease on the endpoint.**
#[tokio::test]
async fn dropping_a_proxy_releases_its_listener() {
    let (listener, port) = upstream().await;
    let allow = || EgressAllowlist::exact([("example.com", 443_u16)]).expect("a pair");
    {
        let _proxy = EgressProxy::accept_on(listener, allow(), wide()).expect("accepts");
        // Dropped here WITHOUT `close`, which is the error path this covers.
    }
    // The accept task's abort lands when the runtime cancels it, not at the drop —
    // poll the rebind rather than asserting the first try.
    let rebound = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
                return listener;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a dropped proxy must not hold its endpoint past the drop");
    let _ = EgressProxy::accept_on(rebound, allow(), wide())
        .expect("a dropped proxy left nothing behind")
        .close()
        .await;
}

/// **A refusal's durable row carries the kind, the status the guest saw, the
/// authority the guest named, and the sentence an operator reads.**
///
/// `EgressRefusal::report` is what `CompletedCapsule` persists; a row that lost the
/// authority the guest asked for — or the status the wire carried — is evidence that
/// cannot be audited back to the request. The variants are exercised directly because
/// the report is a pure projection of the refusal: no proxy needs to run for the
/// projection to be scored.
#[test]
fn a_refusal_reports_kind_status_authority_and_sentence() {
    let attempt_id = ulid::Ulid::new();

    let report = EgressRefusal::MethodNotConnect {
        method: "GOPHER".to_owned(),
    }
    .report(attempt_id, 7);
    assert_eq!(report.attempt_id, attempt_id);
    assert_eq!(report.seq, 7);
    assert_eq!(report.kind, EgressRefusalKind::MethodNotConnect);
    assert_eq!(report.status, Some(405), "the wire answered 405");
    assert_eq!(
        report.authority, "GOPHER",
        "the verbatim token the client sent is the row's authority"
    );
    assert_eq!(report.port, 0);
    assert!(
        report.detail.contains("GOPHER"),
        "the sentence names the method: {:?}",
        report.detail
    );

    let report = EgressRefusal::UpstreamUnreachable {
        authority: "api.example.com:443".to_owned(),
        error: "refused".to_owned(),
    }
    .report(attempt_id, 8);
    assert_eq!(report.kind, EgressRefusalKind::UpstreamUnreachable);
    assert_eq!(report.status, Some(502));
    assert_eq!(report.authority, "api.example.com:443");
    assert_eq!(report.port, 0);

    let report = EgressRefusal::HostNotAllowed {
        host: "api.example.com".to_owned(),
        port: 8443,
    }
    .report(attempt_id, 9);
    assert_eq!(report.kind, EgressRefusalKind::HostNotAllowed);
    assert_eq!(report.status, Some(403));
    assert_eq!(report.authority, "api.example.com");
    assert_eq!(report.port, 8443, "the asked-for port survives");

    let report = EgressRefusal::IdleTimeout {
        authority: "api.example.com:443".to_owned(),
        idle_ms: 10_000,
    }
    .report(attempt_id, 10);
    assert_eq!(report.kind, EgressRefusalKind::IdleTimeout);
    assert_eq!(
        report.status, None,
        "a refusal only reachable inside an opaque tunnel has no HTTP status"
    );
    assert_eq!(report.authority, "api.example.com:443");
    assert!(
        !report.detail.is_empty(),
        "the sentence is written, not an empty string"
    );
}

/// **The refusal record stops at [`REFUSAL_RECORD_LIMIT`] and counts the rest.**
///
/// `refusals_dropped` is the number a reader adds to the stored rows to recover
/// "served", so the cap must bound the WIRE rows (the list a `CompletedCapsule`
/// frame carries) while the counter keeps the accounting honest — a record that
/// grew past the cap, or a counter that read zero when rows were dropped, would
/// both report a refusal volume the attempt did not have.
#[tokio::test]
async fn the_refusal_record_stops_at_its_cap_and_counts_the_rest() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    const OVER: usize = 2;
    for _ in 0..(kata_worker::egress_proxy::REFUSAL_RECORD_LIMIT + OVER) {
        let mut client = TcpStream::connect(proxy.local_addr())
            .await
            .expect("the proxy accepts");
        client
            .write_all(connect_request("not-allowed.example.com:443").as_bytes())
            .await
            .expect("the request is writable");
        // Half-close so the answer-side drain sees EOF instead of waiting its
        // deadline out on every one of the 500+ iterations.
        client.shutdown().await.expect("the write half closes");
        let mut head = Vec::new();
        client
            .read_to_end(&mut head)
            .await
            .expect("a refused client is answered and closed");
        assert!(
            String::from_utf8_lossy(&head).contains("X-Kata-Egress-Refused: host_not_allowed"),
            "every refused request is answered"
        );
    }
    assert_eq!(
        proxy.refusals().await.len(),
        kata_worker::egress_proxy::REFUSAL_RECORD_LIMIT,
        "the record holds exactly the cap — the {OVER} past it are not wire rows"
    );
    assert_eq!(
        proxy.refusals_dropped(),
        OVER as u64,
        "and the dropped count is what a reader adds back to recover 'served'"
    );
    let _ = listener;
    let _ = proxy.close().await;
}

/// **An HTTP version kata does not speak is a 400 — and `HTTP/1.0` still opens a
/// tunnel.**
///
/// The version check accepts exactly the two versions it names: a request line at
/// any other version is `malformed_request_line`, while an `HTTP/1.0` CONNECT is
/// well-formed and must reach the upstream. Both directions are asserted because a
/// check that only ever refused — or one that accepted a version it never parsed —
/// fails one of them.
#[tokio::test]
async fn an_http_version_kata_does_not_speak_is_a_400() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let head = exchange(
        &proxy,
        &format!("CONNECT 127.0.0.1:{port} HTTP/9.9\r\n\r\n"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 400 Bad Request"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: malformed_request_line"));

    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client
        .write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.0\r\n\r\n").as_bytes())
        .await
        .expect("writable");
    let (_server, _) = listener
        .accept()
        .await
        .expect("the HTTP/1.0 CONNECT reached the upstream");
    let mut established = [0_u8; 39];
    client
        .read_exact(&mut established)
        .await
        .expect("200 Connection established");
    drop(client);
    let _ = proxy.close().await;
}

/// **The header-block cap counts wire bytes, terminators included.**
///
/// Each header line consumes `len + 2` against the cap — the line plus its CRLF,
/// because the cap bounds what the guest SENT, not what survived parsing. A block
/// of two one-byte headers and the bare terminator is 8 wire bytes: a cap of 7
/// must refuse it AT the terminator, and an accounting that dropped the
/// terminator's bytes would let the block through the bound it crossed.
#[tokio::test]
async fn a_header_block_is_counted_in_wire_bytes_terminators_included() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(
        port,
        EgressBudgets {
            max_header_block_bytes: 7,
            ..wide()
        },
    )
    .await;

    // `a\r\n` + `b\r\n` is 6 wire bytes; the `\r\n` terminator makes 8 — over 7.
    let head = exchange(
        &proxy,
        &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\na\r\nb\r\n\r\n"),
    )
    .await;
    assert!(
        head.starts_with("HTTP/1.1 431 Request Header Fields Too Large"),
        "got {head:?}"
    );
    assert!(head.contains("X-Kata-Egress-Refused: header_block_too_large"));
    never_accepts(&listener, "the header block crossed its cap").await;
    assert_eq!(labels(&proxy).await, vec!["header_block_too_large"]);
}

/// **`CONNECT host:0` is named unconnectable, not a spelling problem.**
///
/// `0` is one digit and canonical — it parses cleanly and is refused as a port
/// nothing can listen on, which is a different diagnosis than a leading zero.
/// The recorded sentence is where the distinction lives, so the assertion reads
/// the refusal's own rendering, not the wire label both diagnostics share.
#[tokio::test]
async fn a_port_of_zero_is_named_unconnectable() {
    let (listener, port) = upstream().await;
    let proxy = proxy_for(port, wide()).await;

    let head = exchange(&proxy, &connect_request("127.0.0.1:0")).await;
    assert!(head.starts_with("HTTP/1.1 400 Bad Request"), "got {head:?}");
    assert!(head.contains("X-Kata-Egress-Refused: malformed_authority"));
    never_accepts(&listener, "port 0 is unconnectable").await;

    let refusals = proxy.refusals().await;
    assert_eq!(refusals.len(), 1);
    assert!(
        refusals[0].to_string().contains("unconnectable"),
        "port 0 is refused for what it is, not for how it is spelled: {:?}",
        refusals[0]
    );
    let _ = proxy.close().await;
}

/// **`close` stays bounded when a tunnel's upstream dial never answers.**
///
/// A `TunnelSlot` is acquired BEFORE the dial, so a dial that never completes
/// holds a live tunnel against the observation `close` makes: the grace window
/// must expire into the abort, not wait on the slot. `close` is driven under a
/// test deadline so a close that waited on the slot is a hang, not a slow
/// verdict — the property is that close returns AT ALL, and the slot's drop on
/// the aborted task is what turns `live` to zero in time.
#[tokio::test]
async fn close_bounds_a_tunnel_whose_dial_never_answers() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("the proxy's accept source binds on loopback");
    let proxy = EgressProxy::accept_on_dialing(
        listener,
        EgressAllowlist::exact([("dangling.example.com", 443_u16)]).expect("a pair"),
        wide(),
        |_, _| Box::pin(std::future::pending::<Result<TcpStream, EgressRefusal>>()),
    )
    .expect("sane budgets");

    let mut client = TcpStream::connect(proxy.local_addr())
        .await
        .expect("the proxy accepts");
    client
        .write_all(connect_request("dangling.example.com:443").as_bytes())
        .await
        .expect("writable");

    // Wait until the slot is provably held — the abort's release of it is the
    // behaviour under test, so the close must not race ahead of the acquire.
    let held = tokio::time::timeout(Duration::from_secs(5), async {
        while proxy.live_tunnels() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(held.is_ok(), "the pending dial holds a tunnel slot");

    let outcome = tokio::time::timeout(Duration::from_secs(10), proxy.close())
        .await
        .expect(
            "close is bounded even with a dial that never answers — the grace \
                 window expires into the abort, it does not wait on the slot",
        );
    assert!(
        matches!(
            outcome,
            TeardownOutcome::Confirmed { .. } | TeardownOutcome::Ambiguous { .. }
        ),
        "close returned a verdict, which is the property: {outcome:?}"
    );
    drop(client);
}
