//! Mock model providers: the OpenAI Responses API (HTTP + SSE, and WebSocket)
//! and the Anthropic Messages API (HTTP + SSE), each on a loopback port.
//!
//! Every event here is WRITTEN BY HAND from the published wire shapes; no byte
//! was captured from a real provider. Each mock keeps its OWN log of the request
//! bodies it received, in order, recorded the moment a body is read and before
//! any reply: that log is the witness a cell reads for "the request was sent"
//! and "the next request never arrived". It logs every HTTP request's head
//! (its request line and headers) beside it.
//!
//! Only a model call takes a reply: over HTTP a `POST`. Any other HTTP request
//! is answered `404`, logged nowhere and takes no reply, so a read another test
//! process sends to a port it took for unbound, and this mock bound, cannot
//! leave a turn's call without its reply (`nanocode_qualification`'s
//! `a_stray_read_takes_no_scripted_reply_from_the_mock_provider`). A stray
//! `POST` would still take one.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How the mock answers one request.
#[derive(Clone, Debug)]
pub enum Reply {
    /// Stream these events and end the response.
    Events(Vec<Value>),
    /// Record the request and never answer.
    Stall,
    /// Record the request and drop the connection without a byte.
    Drop,
    /// Record the request, wait this long, then drop the connection without a
    /// byte.
    DropAfter(Duration),
    /// Record the request and answer it with this HTTP status and JSON body.
    Status(u16, Value),
    /// [`Reply::Status`] with these extra response headers, each `name` and
    /// `value` as written.
    StatusWith(u16, Vec<(&'static str, String)>, Value),
    /// Record the request, begin a response that carries all of these events
    /// — over HTTP its head declares their whole length — stream every event
    /// but the last, and drop the connection: the response ends mid-body,
    /// before its terminal event, as a provider connection lost mid-response
    /// does.
    DropMidResponse(Vec<Value>),
    /// Record the request, wait until the cell opens this [`Gate`], then
    /// answer it as the inner reply: a cell that must observe something
    /// before the model answers holds the answer on that event, never on a
    /// sleep.
    Gated(Gate, Box<Reply>),
    /// Record the request, stream `head`, wait until the cell opens `gate`,
    /// then stream `rest` and end the response — over HTTP its head declares
    /// the whole length. The pause is the one way to make a client read
    /// `head` alone: events a client finds already buffered it may coalesce.
    Paused {
        head: Vec<Value>,
        gate: Gate,
        rest: Vec<Value>,
    },
}

/// An event a [`Reply::Gated`] answer waits on: closed until the cell opens it,
/// open for good after.
#[derive(Clone, Default)]
pub struct Gate(Arc<tokio::sync::watch::Sender<bool>>);

impl std::fmt::Debug for Gate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("Gate")
            .field(&*self.0.borrow())
            .finish()
    }
}

impl Gate {
    /// Opens the gate: every answer waiting on it, and every later one, goes.
    pub fn open(&self) {
        self.0.send_replace(true);
    }

    async fn opened(&self) {
        let mut open = self.0.subscribe();
        // The sender lives in `self`, so the wait ends only when it opens.
        let _ = open.wait_for(|open| *open).await;
    }
}

/// `reply`, once every gate it is held behind is open: never a
/// [`Reply::Gated`].
async fn ungated(mut reply: Reply) -> Reply {
    while let Reply::Gated(gate, inner) = reply {
        gate.opened().await;
        reply = *inner;
    }
    reply
}

/// Answers one request from its body: a mock whose replies depend on what the
/// request carries rather than on its place in a script.
pub type Responder = Arc<dyn Fn(&Value) -> Reply + Send + Sync>;

#[derive(Clone, Default)]
struct Shared {
    log: Arc<Mutex<Vec<Value>>>,
    /// The head of every HTTP request, its request line and headers as they
    /// arrived, in order: the witness of what a request names outside its
    /// body.
    heads: Arc<Mutex<Vec<String>>>,
    /// The `authorization` header of every HTTP request, in order: the
    /// witness of which credential reached the provider.
    authorizations: Arc<Mutex<Vec<String>>>,
    script: Arc<Mutex<VecDeque<Reply>>>,
    /// Set by [`MockProvider::start_responding`]: it answers every request, and
    /// `script` is never read.
    responder: Option<Responder>,
    /// Set by [`MockProvider::start_holding_websocket`].
    hold: Option<Arc<HandshakeHold>>,
}

/// WebSocket handshakes held in flight: each accepted connection waits here,
/// its TCP connect done and its upgrade unanswered, until released.
#[derive(Default)]
struct HandshakeHold {
    accepted: Mutex<usize>,
    released: tokio::sync::watch::Sender<bool>,
}

impl Shared {
    fn next_reply(&self, body: &Value) -> Reply {
        if let Some(responder) = &self.responder {
            return responder(body);
        }
        self.script
            .lock()
            .expect("script")
            .pop_front()
            .unwrap_or(Reply::Stall)
    }

    fn record(&self, body: Value) {
        self.log.lock().expect("log").push(body);
    }
}

/// A running mock provider.
pub struct MockProvider {
    /// The HTTP base: `http://127.0.0.1:<port>/v1`.
    pub url: String,
    /// The WebSocket endpoint: `ws://127.0.0.1:<port>/v1/responses`.
    pub ws_url: String,
    shared: Shared,
}

impl MockProvider {
    /// Serve `script`, one reply per request, on both transports.
    pub async fn start(script: Vec<Reply>) -> Self {
        Self::serve(Shared {
            log: Arc::default(),
            heads: Arc::default(),
            authorizations: Arc::default(),
            script: Arc::new(Mutex::new(script.into())),
            responder: None,
            hold: None,
        })
        .await
    }

    /// Answer every request, on both transports, with what `responder` makes of
    /// its body (logged first, as every body is).
    pub async fn start_responding(responder: Responder) -> Self {
        Self::serve(Shared {
            log: Arc::default(),
            heads: Arc::default(),
            authorizations: Arc::default(),
            script: Arc::default(),
            responder: Some(responder),
            hold: None,
        })
        .await
    }

    /// Serve `script` as [`Self::start`] does, but hold every WebSocket
    /// handshake in flight (the client's `Connect` attempt) until
    /// [`Self::release_handshakes`].
    pub async fn start_holding_websocket(script: Vec<Reply>) -> Self {
        Self::serve(Shared {
            log: Arc::default(),
            heads: Arc::default(),
            authorizations: Arc::default(),
            script: Arc::new(Mutex::new(script.into())),
            responder: None,
            hold: Some(Arc::default()),
        })
        .await
    }

    /// Resolve once a WebSocket connection is held in its handshake.
    pub async fn wait_for_held_handshake(&self) {
        let hold = self.shared.hold.as_ref().expect("a holding mock");
        while *hold.accepted.lock().expect("accepted") == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Answer every held handshake, and every later one at once.
    pub fn release_handshakes(&self) {
        let hold = self.shared.hold.as_ref().expect("a holding mock");
        hold.released.send_replace(true);
    }

    async fn serve(shared: Shared) -> Self {
        let http = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
        let ws = TcpListener::bind("127.0.0.1:0").await.expect("bind ws");
        let url = format!("http://{}/v1", http.local_addr().expect("addr"));
        let ws_url = format!("ws://{}/v1/responses", ws.local_addr().expect("addr"));
        tokio::spawn(serve_http(http, shared.clone()));
        tokio::spawn(serve_ws(ws, shared.clone()));
        Self {
            url,
            ws_url,
            shared,
        }
    }

    /// Every request body received, in order.
    pub fn requests(&self) -> Vec<Value> {
        self.shared.log.lock().expect("log").clone()
    }

    /// How many requests [`Self::requests`] holds, read through a handle that
    /// outlives a borrow of the mock: a thread off the cell's runtime counts
    /// them while the runtime drives the turn.
    pub fn request_counter(&self) -> impl Fn() -> usize + Send + 'static {
        let log = Arc::clone(&self.shared.log);
        move || log.lock().expect("log").len()
    }

    /// The head of every HTTP request received (its request line and
    /// headers), in order.
    pub fn heads(&self) -> Vec<String> {
        self.shared.heads.lock().expect("heads").clone()
    }

    /// The `authorization` header of every HTTP request received, in order.
    pub fn authorizations(&self) -> Vec<String> {
        self.shared
            .authorizations
            .lock()
            .expect("authorizations")
            .clone()
    }

    /// Resolve once `count` request bodies have been received.
    pub async fn wait_for_requests(&self, count: usize) {
        while self.shared.log.lock().expect("log").len() < count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// The loopback address every connect is refused at: port 1, below
/// `net.ipv4.ip_unprivileged_port_start` (1024 by default), so no unprivileged
/// process — no other cell's mock in a parallel run — can bind it. A port read
/// off a dropped `127.0.0.1:0` listener is free for the next bind to take.
pub const REFUSED_ADDR: &str = "127.0.0.1:1";

/// A loopback URL nothing listens on: every connect is refused.
pub fn refused_url() -> (String, String) {
    (
        format!("http://{REFUSED_ADDR}/v1"),
        format!("ws://{REFUSED_ADDR}/v1/responses"),
    )
}

async fn serve_http(listener: TcpListener, shared: Shared) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(serve_http_connection(socket, shared.clone()));
    }
}

/// One HTTP/1.1 connection, possibly keep-alive: read a request, answer it.
async fn serve_http_connection(mut socket: TcpStream, shared: Shared) {
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        let Some((head_end, length)) = Box::pin(read_head(&mut socket, &mut buffer)).await else {
            return;
        };
        while buffer.len() < head_end + length {
            let mut chunk = vec![0_u8; 65536].into_boxed_slice();
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        if !head.starts_with("POST ") {
            buffer.drain(..head_end + length);
            let refusal = "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n";
            if socket.write_all(refusal.as_bytes()).await.is_err() {
                return;
            }
            continue;
        }
        if let Some(authorization) = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_owned())
        }) {
            shared
                .authorizations
                .lock()
                .expect("authorizations")
                .push(authorization);
        }
        shared.heads.lock().expect("heads").push(head);
        let body: Vec<u8> = buffer.drain(..head_end + length).skip(head_end).collect();
        let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        shared.record(value.clone());
        match ungated(shared.next_reply(&value)).await {
            Reply::Events(events) => {
                let text = sse_text(&events);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: \
                     {}\r\n\r\n{text}",
                    text.len()
                );
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
            Reply::Stall => {
                std::future::pending::<()>().await;
            }
            Reply::Drop => return,
            Reply::DropAfter(wait) => {
                tokio::time::sleep(wait).await;
                return;
            }
            Reply::Status(status, body) => {
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Mock\r\ncontent-type: application/json\r\ncontent-length: \
                     {}\r\n\r\n{body}",
                    body.len()
                );
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
            Reply::StatusWith(status, headers, body) => {
                let body = body.to_string();
                let headers = headers
                    .iter()
                    .fold(String::new(), |mut out, (name, value)| {
                        use std::fmt::Write as _;
                        let _ = write!(out, "{name}: {value}\r\n");
                        out
                    });
                let response = format!(
                    "HTTP/1.1 {status} Mock\r\ncontent-type: application/json\r\n{headers}\
                     content-length: {}\r\n\r\n{body}",
                    body.len()
                );
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
            Reply::Gated(..) => unreachable!("`ungated` answers what a gate holds"),
            Reply::Paused { head, gate, rest } => {
                let first = sse_text(&head);
                let then = sse_text(&rest);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: \
                     {}\r\n\r\n{first}",
                    first.len() + then.len()
                );
                if socket.write_all(response.as_bytes()).await.is_err()
                    || socket.flush().await.is_err()
                {
                    return;
                }
                gate.opened().await;
                if socket.write_all(then.as_bytes()).await.is_err() {
                    return;
                }
            }
            Reply::DropMidResponse(events) => {
                let sent = sse_text(&events[..events.len().saturating_sub(1)]);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: \
                     {}\r\n\r\n{sent}",
                    sse_text(&events).len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
                return;
            }
        }
    }
}

/// `events` as a `text/event-stream` body: each one an `event:` line naming
/// its `type` and a `data:` line carrying it.
fn sse_text(events: &[Value]) -> String {
    let mut text = String::new();
    for event in events {
        let name = event["type"].as_str().unwrap_or("message");
        let _ = write!(text, "event: {name}\ndata: {event}\n\n");
    }
    text
}

/// Read until a full request head is buffered; answers its end and the
/// declared body length.
async fn read_head(socket: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<(usize, usize)> {
    loop {
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..at]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0);
            return Some((at + 4, length));
        }
        let mut chunk = vec![0_u8; 65536].into_boxed_slice();
        match socket.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
}

async fn serve_ws(listener: TcpListener, shared: Shared) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Some(hold) = shared.hold.as_ref() {
                *hold.accepted.lock().expect("accepted") += 1;
                let mut released = hold.released.subscribe();
                if released.wait_for(|released| *released).await.is_err() {
                    return;
                }
            }
            let Ok(mut socket) = tokio_tungstenite::accept_async(socket).await else {
                return;
            };
            while let Some(Ok(message)) = socket.next().await {
                let tokio_tungstenite::tungstenite::Message::Text(text) = message else {
                    continue;
                };
                let value: Value = serde_json::from_str(text.as_str()).unwrap_or(Value::Null);
                shared.record(value.clone());
                match ungated(shared.next_reply(&value)).await {
                    Reply::Events(events) => {
                        for event in events {
                            let frame =
                                tokio_tungstenite::tungstenite::Message::text(event.to_string());
                            if socket.send(frame).await.is_err() {
                                return;
                            }
                        }
                    }
                    Reply::Stall => std::future::pending::<()>().await,
                    Reply::DropAfter(wait) => {
                        tokio::time::sleep(wait).await;
                        return;
                    }
                    Reply::DropMidResponse(events) => {
                        for event in &events[..events.len().saturating_sub(1)] {
                            let frame =
                                tokio_tungstenite::tungstenite::Message::text(event.to_string());
                            if socket.send(frame).await.is_err() {
                                return;
                            }
                        }
                        return;
                    }
                    Reply::Paused { head, gate, rest } => {
                        let head_len = head.len();
                        for (at, event) in head.into_iter().chain(rest).enumerate() {
                            if at == head_len {
                                gate.opened().await;
                            }
                            let frame =
                                tokio_tungstenite::tungstenite::Message::text(event.to_string());
                            if socket.send(frame).await.is_err() {
                                return;
                            }
                        }
                    }
                    Reply::Drop | Reply::Status(..) | Reply::StatusWith(..) => return,
                    Reply::Gated(..) => unreachable!("`ungated` answers what a gate holds"),
                }
            }
        });
    }
}

// ── Responses events, written by hand ---------------------------------------

/// The `usage` object of a `response.completed`.
pub fn usage(input: u64, cached: u64, output: u64) -> Value {
    json!({
        "input_tokens": input,
        "input_tokens_details": {"cached_tokens": cached},
        "output_tokens": output,
        "total_tokens": input + output,
    })
}

/// A response whose output is one assistant message.
pub fn message_reply(id: &str, text: &str, usage: Value) -> Reply {
    Reply::Events(vec![
        json!({"type": "response.created", "response": {"id": id}}),
        json!({"type": "response.output_text.delta", "output_index": 0, "delta": text}),
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {
                "type": "message",
                "id": format!("msg_{id}"),
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}],
            },
        }),
        json!({
            "type": "response.completed",
            "response": {"id": id, "model": "gpt-6-luna", "usage": usage},
        }),
    ])
}

/// A response with no output item: neither a final message nor a Code Mode
/// call, which nanocode answers by re-prompting once inside the same turn.
pub fn empty_reply(id: &str, usage: Value) -> Reply {
    Reply::Events(vec![
        json!({"type": "response.created", "response": {"id": id}}),
        json!({
            "type": "response.completed",
            "response": {"id": id, "model": "gpt-6-luna", "usage": usage},
        }),
    ])
}

/// A response whose output is one Code Mode `exec` cell running `source`: the
/// model-facing way a codex model calls the host tools, which are nested
/// under the cell's `tools` global and are not directly callable.
pub fn code_reply(id: &str, source: &str, usage: Value) -> Reply {
    Reply::Events(vec![
        json!({"type": "response.created", "response": {"id": id}}),
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {
                "type": "custom_tool_call",
                "id": format!("ct_{id}"),
                "call_id": format!("call_{id}"),
                "name": "exec",
                "input": source,
            },
        }),
        json!({
            "type": "response.completed",
            "response": {"id": id, "model": "gpt-6-luna", "usage": usage},
        }),
    ])
}

/// A response to nanocode's remote compaction request: its one compaction
/// item, opaque to the client, which replaces the compacted history.
pub fn compaction_reply(id: &str, usage: Value) -> Reply {
    Reply::Events(vec![
        json!({"type": "response.created", "response": {"id": id}}),
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {"type": "compaction", "encrypted_content": format!("compacted_{id}")},
        }),
        json!({
            "type": "response.completed",
            "response": {"id": id, "model": "gpt-6-luna", "usage": usage},
        }),
    ])
}

/// A Code Mode cell that runs one `exec_command` with `arguments` and hands
/// its result back as the cell's text.
pub fn exec_command_reply(id: &str, arguments: &Value, usage: Value) -> Reply {
    code_reply(
        id,
        &format!(
            "const result = await tools.exec_command({arguments});\ntext(JSON.stringify(result));"
        ),
        usage,
    )
}

// ── Messages events, written by hand ----------------------------------------

/// A Messages stream whose content is one text block.
pub fn claude_text_reply(text: &str) -> Reply {
    claude_text_reply_using(text, json!({"input_tokens": 10, "output_tokens": 1}), 3)
}

/// [`claude_text_reply`] whose `message_start` states `usage` — the Messages
/// API's own classes: `input_tokens` (the uncached input),
/// `cache_read_input_tokens`, `cache_creation_input_tokens` — and whose
/// `message_delta` states the turn's final `output_tokens`.
pub fn claude_text_reply_using(text: &str, usage: Value, output_tokens: u64) -> Reply {
    Reply::Events(vec![
        json!({
            "type": "message_start",
            "message": {
                "id": "msg_mock", "type": "message", "role": "assistant",
                "model": "claude-mock", "content": [], "stop_reason": null,
                "stop_sequence": null,
                "usage": usage,
            },
        }),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
        json!({"type": "content_block_stop", "index": 0}),
        json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": null},
            "usage": {"output_tokens": output_tokens},
        }),
        json!({"type": "message_stop"}),
    ])
}

/// A Messages stream whose content is one Code Mode `exec` call running
/// `code`: the model-facing way a Claude model calls the host tools under
/// `code_only`.
pub fn claude_code_reply(id: &str, code: &str) -> Reply {
    claude_code_reply_using(id, code, json!({"input_tokens": 10, "output_tokens": 1}), 3)
}

/// [`claude_code_reply`] whose `message_start` states `usage` and whose
/// `message_delta` states the call's final `output_tokens`, as
/// [`claude_text_reply_using`] does.
pub fn claude_code_reply_using(id: &str, code: &str, usage: Value, output_tokens: u64) -> Reply {
    let input = json!({"code": code}).to_string();
    Reply::Events(vec![
        json!({
            "type": "message_start",
            "message": {
                "id": format!("msg_{id}"), "type": "message", "role": "assistant",
                "model": "claude-mock", "content": [], "stop_reason": null,
                "stop_sequence": null,
                "usage": usage,
            },
        }),
        json!({
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "tool_use", "id": format!("toolu_{id}"), "name": "exec", "input": {}},
        }),
        json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": input},
        }),
        json!({"type": "content_block_stop", "index": 0}),
        json!({
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": null},
            "usage": {"output_tokens": output_tokens},
        }),
        json!({"type": "message_stop"}),
    ])
}

/// A response whose output is one Code Mode `wait` call on the running cell
/// `cell_id`; with `terminate`, the call ends that cell.
pub fn wait_reply(id: &str, cell_id: &str, terminate: bool, usage: Value) -> Reply {
    Reply::Events(vec![
        json!({"type": "response.created", "response": {"id": id}}),
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {
                "type": "function_call",
                "id": format!("fc_{id}"),
                "call_id": format!("call_{id}"),
                "name": "wait",
                "arguments": json!({"cell_id": cell_id, "terminate": terminate}).to_string(),
            },
        }),
        json!({
            "type": "response.completed",
            "response": {"id": id, "model": "gpt-6-luna", "usage": usage},
        }),
    ])
}

/// What a Responses request body handed the model as the output of the tool
/// call `call_id`, as JSON text; `None` when the body carries no such output.
pub fn call_output(request: &Value, call_id: &str) -> Option<String> {
    request["input"]
        .as_array()?
        .iter()
        .find(|item| {
            item["call_id"] == call_id
                && item["type"]
                    .as_str()
                    .is_some_and(|kind| kind.ends_with("_call_output"))
        })
        .map(|item| item["output"].to_string())
}

/// Every output a Responses request body handed the model for the tool call
/// `call_id`, in order: the call's result first, then each Code Mode
/// notification nanocode hands the model as an output of its own for that
/// call. A bare string output is a string, a content-item output an array.
pub fn call_outputs(request: &Value, call_id: &str) -> Vec<Value> {
    request["input"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| {
            item["call_id"] == call_id
                && item["type"]
                    .as_str()
                    .is_some_and(|kind| kind.ends_with("_call_output"))
        })
        .map(|item| item["output"].clone())
        .collect()
}

/// The texts a Messages request body handed the model as the `tool_result` of
/// `tool_use_id`, in order: a bare string content, or the `text` of each block
/// that has one. `None` when the body carries no such result.
pub fn tool_result_texts(request: &Value, tool_use_id: &str) -> Option<Vec<String>> {
    let result = request["messages"]
        .as_array()?
        .iter()
        .filter_map(|message| message["content"].as_array())
        .flatten()
        .find(|block| block["type"] == "tool_result" && block["tool_use_id"] == tool_use_id)?;
    Some(match &result["content"] {
        Value::String(text) => vec![text.clone()],
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|block| block["text"].as_str())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    })
}
