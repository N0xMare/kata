use std::path::{Path, PathBuf};

use super::*;

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len())
        .expect("test bodies fit a u32")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(body);
    out
}

fn read_worker(bytes: &[u8]) -> Result<WorkerFrame, FrameError> {
    read_frame(&mut &bytes[..])
}

fn read_toolhost(bytes: &[u8]) -> Result<ToolhostFrame, FrameError> {
    read_frame(&mut &bytes[..])
}

fn malformed(result: Result<impl std::fmt::Debug, FrameError>, needle: &str) {
    match result {
        Err(FrameError::Malformed(message)) => {
            assert!(message.contains(needle), "{message:?} lacks {needle:?}");
        }
        other => panic!("expected a Malformed refusal naming {needle:?}, got {other:?}"),
    }
}

fn every_worker_frame() -> Vec<WorkerFrame> {
    let (id, session) = (RequestId(7), SessionId(3));
    vec![
        WorkerFrame::Exec {
            id,
            session,
            shell: Some("bash".into()),
            login: true,
            script: "printf hi".into(),
            workdir: None,
        },
        WorkerFrame::Stdin {
            session,
            data_b64: Chunk::new(b"\x00\xffyes\n".to_vec()).unwrap(),
            close: true,
        },
        WorkerFrame::Signal {
            session,
            signal: SignalKind::Interrupt,
        },
        WorkerFrame::KillAll { id },
        WorkerFrame::ReadFile {
            id,
            path: "/work/a".into(),
        },
        WorkerFrame::WriteFile {
            id,
            path: "/work/a".into(),
            data_b64: FileBody::new(b"\xff\x00not utf-8".to_vec()).unwrap(),
        },
        WorkerFrame::RemoveFile {
            id,
            path: "/work/a".into(),
        },
        WorkerFrame::Shutdown { id },
    ]
}

fn every_toolhost_frame() -> Vec<ToolhostFrame> {
    let (id, session) = (RequestId(7), SessionId(3));
    vec![
        ToolhostFrame::Hello(Hello::current()),
        ToolhostFrame::Started {
            id,
            session,
            pid: 42,
            note: Some("bash is not on PATH; ran sh".into()),
        },
        ToolhostFrame::SpawnFailed {
            id,
            session,
            errno: 11,
            message: "EAGAIN".into(),
        },
        ToolhostFrame::Output {
            session,
            stream: Stream::Stderr,
            data_b64: Chunk::new(vec![0xde, 0xad]).unwrap(),
        },
        ToolhostFrame::Exited {
            session,
            code: None,
            signal: Some(9),
        },
        ToolhostFrame::SessionGone { session },
        ToolhostFrame::FileBytes {
            id,
            data_b64: Some(FileBody::new(vec![0x89, b'P', b'N', b'G']).unwrap()),
        },
        ToolhostFrame::FileError {
            id,
            errno: 30,
            message: "EROFS".into(),
        },
        ToolhostFrame::Done { id },
        ToolhostFrame::Bye { id, reaped: 2 },
        ToolhostFrame::Error {
            id: None,
            message: "unknown variant".into(),
        },
    ]
}

#[test]
fn codec_a_zero_length_frame_is_refused() {
    assert!(matches!(
        read_worker(&[0, 0, 0, 0]),
        Err(FrameError::EmptyBody)
    ));
    assert!(matches!(
        read_toolhost(&[0, 0, 0, 0]),
        Err(FrameError::EmptyBody)
    ));
}

#[test]
fn codec_a_length_over_8_mib_is_refused_on_read_and_on_write() {
    let over = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes();
    assert!(matches!(
        read_worker(&over),
        Err(FrameError::BodyTooLarge { declared, .. }) if declared == MAX_FRAME_BYTES + 1
    ));
    let huge = WorkerFrame::Exec {
        id: RequestId(1),
        session: SessionId(1),
        shell: None,
        login: false,
        script: "x".repeat(MAX_FRAME_BYTES),
        workdir: None,
    };
    assert!(matches!(
        encode_frame(&huge),
        Err(FrameError::BodyTooLarge { .. })
    ));
}

/// A read in one direction, the frame rendered for a failure message.
type Read = fn(&[u8]) -> Result<String, FrameError>;

/// Every frame of both directions, as the JSON a peer sends, with its `kind`
/// and the read of its direction.
fn every_frame_as_json() -> Vec<(String, serde_json::Value, Read)> {
    fn as_json(frame: impl Serialize, read: Read) -> (String, serde_json::Value, Read) {
        let value = serde_json::to_value(frame).unwrap();
        (value["kind"].as_str().unwrap().to_owned(), value, read)
    }
    let worker: Read = |bytes| read_worker(bytes).map(|frame| format!("{frame:?}"));
    let toolhost: Read = |bytes| read_toolhost(bytes).map(|frame| format!("{frame:?}"));
    let mut frames: Vec<_> = every_worker_frame()
        .into_iter()
        .map(|frame| as_json(frame, worker))
        .collect();
    frames.extend(
        every_toolhost_frame()
            .into_iter()
            .map(|frame| as_json(frame, toolhost)),
    );
    frames
}

fn read_json(read: Read, value: &serde_json::Value) -> Result<String, FrameError> {
    read(&framed(&serde_json::to_vec(value).unwrap()))
}

#[test]
fn codec_an_unknown_field_is_refused() {
    // Literal bodies, independent of this build's serializer: a struct variant
    // of each direction, the Hello struct, and the envelope of each direction
    // (where serde names the two keys it accepts instead).
    malformed(
        read_worker(&framed(
            br#"{"kind":"kill_all","frame":{"id":1,"extra":true}}"#,
        )),
        "unknown field `extra`",
    );
    malformed(
        read_toolhost(&framed(br#"{"kind":"done","frame":{"id":1,"extra":1}}"#)),
        "unknown field `extra`",
    );
    malformed(
        read_toolhost(&framed(
            br#"{"kind":"hello","frame":{"protocol":1,"source_digest":"ab","extra":1}}"#,
        )),
        "unknown field `extra`",
    );
    let envelope = r#"invalid value: string "extra", expected "kind" or "frame""#;
    malformed(
        read_worker(&framed(
            br#"{"kind":"shutdown","frame":{"id":1},"extra":1}"#,
        )),
        envelope,
    );
    malformed(
        read_toolhost(&framed(br#"{"kind":"done","frame":{"id":1},"extra":1}"#)),
        envelope,
    );
    // And every frame of both directions, in the frame and on the envelope.
    for (kind, frame, read) in every_frame_as_json() {
        let mut inner = frame.clone();
        inner["frame"]["extra"] = serde_json::json!(1);
        let refusal = read_json(read, &inner);
        assert!(
            matches!(&refusal, Err(FrameError::Malformed(m)) if m.contains("unknown field `extra`")),
            "{kind}: an extra frame field gave {refusal:?}"
        );
        let mut outer = frame;
        outer["extra"] = serde_json::json!(1);
        let refusal = read_json(read, &outer);
        assert!(
            matches!(&refusal, Err(FrameError::Malformed(m)) if m.contains(envelope)),
            "{kind}: an extra envelope field gave {refusal:?}"
        );
    }
}

#[test]
fn codec_an_unknown_frame_type_is_refused() {
    // One read and one write verb carry every file's bytes: there is no
    // separate binary verb, and protocol 1's text answer is gone.
    for kind in [
        "list",
        "stat",
        "glob",
        "search",
        "view_image",
        "cancel",
        "read_bytes",
        "write_bytes",
    ] {
        let body = format!(r#"{{"kind":"{kind}","frame":{{"id":1,"path":"/work"}}}}"#);
        malformed(read_worker(&framed(body.as_bytes())), "unknown variant");
    }
    malformed(
        read_toolhost(&framed(
            br#"{"kind":"file_text","frame":{"id":1,"contents":null}}"#,
        )),
        "unknown variant",
    );
    // A frame of the other direction is not a frame of this one.
    malformed(
        read_worker(&framed(br#"{"kind":"done","frame":{"id":1}}"#)),
        "unknown variant",
    );
    malformed(
        read_toolhost(&framed(br#"{"kind":"kill_all","frame":{"id":1}}"#)),
        "unknown variant",
    );
}

#[test]
fn codec_an_absent_field_is_refused_option_fields_included() {
    // Each field of every frame of both directions, dropped in turn.
    let mut dropped = Vec::new();
    for (kind, frame, read) in every_frame_as_json() {
        let keys: Vec<String> = frame["frame"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for key in keys {
            let mut absent = frame.clone();
            absent["frame"].as_object_mut().unwrap().remove(&key);
            let refusal = read_json(read, &absent);
            let needle = format!("missing field `{key}`");
            assert!(
                matches!(&refusal, Err(FrameError::Malformed(m)) if m.contains(&needle)),
                "{kind}.{key}: an absent key gave {refusal:?}"
            );
            dropped.push((kind.clone(), key));
        }
    }
    // The table reached every Option field: the keys whose absence serde would
    // otherwise read as None. `file_bytes.data_b64` is the costliest: a dropped
    // key would read as "the file does not exist".
    for (kind, key) in [
        ("exec", "shell"),
        ("exec", "workdir"),
        ("started", "note"),
        ("exited", "code"),
        ("exited", "signal"),
        ("file_bytes", "data_b64"),
        ("error", "id"),
    ] {
        assert!(
            dropped.contains(&(kind.to_owned(), key.to_owned())),
            "{kind}.{key} was not dropped"
        );
    }
    // `null` is the spelling of None, and it decodes.
    assert_eq!(
        read_toolhost(&framed(
            br#"{"kind":"exited","frame":{"session":1,"code":0,"signal":null}}"#,
        ))
        .unwrap(),
        ToolhostFrame::Exited {
            session: SessionId(1),
            code: Some(0),
            signal: None,
        }
    );
}

#[test]
fn codec_a_body_that_is_not_json_is_refused() {
    for (body, needle) in [
        (&b"<frame/>"[..], "expected value at line 1 column 1"),
        (b"{\"kind\":", "EOF while parsing a value"),
        (b"\"\xff\"", "invalid unicode code point"),
    ] {
        malformed(read_worker(&framed(body)), needle);
        malformed(read_toolhost(&framed(body)), needle);
    }
}

#[test]
fn codec_a_chunk_over_64_kib_or_not_canonical_base64_is_refused() {
    use base64::Engine as _;
    let output = |raw: &str| {
        framed(
            format!(
                r#"{{"kind":"output","frame":{{"session":1,"stream":"stdout","data_b64":"{raw}"}}}}"#
            )
            .as_bytes(),
        )
    };
    let at_cap = STANDARD.encode(vec![b'a'; MAX_CHUNK_BYTES]);
    assert!(read_toolhost(&output(&at_cap)).is_ok());
    // One byte over: its base64 is no longer than the longest canonical
    // encoding of the cap, so the exact count after decoding refuses it.
    let over = STANDARD.encode(vec![b'a'; MAX_CHUNK_BYTES + 1]);
    malformed(
        read_toolhost(&output(&over)),
        "at most 65536 bytes; this one carried 65537",
    );
    // Three bytes over: its base64 is longer than any canonical encoding of the
    // cap, refused by length before decoding.
    let far_over = STANDARD.encode(vec![b'a'; MAX_CHUNK_BYTES + 3]);
    malformed(
        read_toolhost(&output(&far_over)),
        "at most 65536 bytes; this one's base64 is 87388 characters",
    );
    // So a string that long is refused by length even when it is not base64.
    malformed(
        read_toolhost(&output(&"!".repeat(87_385))),
        "this one's base64 is 87385 characters",
    );
    assert_eq!(
        Chunk::new(vec![0; MAX_CHUNK_BYTES + 1]),
        Err(ChunkTooLarge(MAX_CHUNK_BYTES + 1))
    );
    malformed(read_toolhost(&output("not base64!")), "Invalid");
    // Unpadded is not canonical.
    malformed(read_toolhost(&output("aGk")), "Invalid");
}

#[test]
fn codec_a_file_body_over_4_mib_or_not_canonical_base64_is_refused() {
    use base64::Engine as _;
    let write_file = |raw: &str| {
        framed(
            format!(
                r#"{{"kind":"write_file","frame":{{"id":1,"path":"/work/a","data_b64":"{raw}"}}}}"#
            )
            .as_bytes(),
        )
    };
    let file_bytes = |raw: &str| {
        framed(
            format!(r#"{{"kind":"file_bytes","frame":{{"id":1,"data_b64":"{raw}"}}}}"#).as_bytes(),
        )
    };
    let at_cap = STANDARD.encode(vec![0xff; MAX_FILE_BYTES]);
    assert!(read_worker(&write_file(&at_cap)).is_ok());
    assert!(read_toolhost(&file_bytes(&at_cap)).is_ok());
    // One byte over: its base64 is no longer than the longest canonical encoding
    // of the cap, so the exact count after decoding refuses it, by name, in
    // either direction.
    let over = STANDARD.encode(vec![0xff; MAX_FILE_BYTES + 1]);
    let exact = "toolhost_file_too_large: a toolhost file body carries at most 4194304 bytes; \
                 this one carried 4194305";
    malformed(read_worker(&write_file(&over)), exact);
    malformed(read_toolhost(&file_bytes(&over)), exact);
    // Three bytes over: its base64 is longer than any canonical encoding of the
    // cap, refused by length before decoding, so even a string that is not
    // base64 is refused by name.
    let far_over = STANDARD.encode(vec![0xff; MAX_FILE_BYTES + 3]);
    malformed(
        read_toolhost(&file_bytes(&far_over)),
        "toolhost_file_too_large: a toolhost file body carries at most 4194304 bytes; this \
         one's base64 is 5592412 characters",
    );
    malformed(
        read_worker(&write_file(&"!".repeat(5_592_409))),
        "toolhost_file_too_large: a toolhost file body carries at most 4194304 bytes; this \
         one's base64 is 5592409 characters",
    );
    // A body over the cap cannot be built to send.
    assert_eq!(
        FileBody::new(vec![0; MAX_FILE_BYTES + 1]),
        Err(FileTooLarge(MAX_FILE_BYTES + 1))
    );
    assert!(FileBody::new(vec![0; MAX_FILE_BYTES]).is_ok());
    malformed(read_toolhost(&file_bytes("not base64!")), "Invalid");
    // Unpadded is not canonical.
    malformed(read_worker(&write_file("aGk")), "Invalid");
}

/// The cap is one a frame can carry: a `WriteFile` of a body at the cap with a
/// `PATH_MAX`-long path, and a `FileBytes` at the cap, each encode under
/// [`MAX_FRAME_BYTES`] and round-trip. The body is all `"`, the byte a JSON
/// string would escape; base64 does not care.
#[test]
fn a_file_body_at_the_cap_fits_one_frame() {
    let body = FileBody::new(vec![b'"'; MAX_FILE_BYTES]).unwrap();
    let write = WorkerFrame::WriteFile {
        id: RequestId(u64::MAX),
        path: format!("/{}", "a".repeat(4095)),
        data_b64: body.clone(),
    };
    let bytes = encode_frame(&write).expect("a write at the cap fits one frame");
    assert_eq!(read_worker(&bytes).unwrap(), write);
    let read = ToolhostFrame::FileBytes {
        id: RequestId(u64::MAX),
        data_b64: Some(body),
    };
    let bytes = encode_frame(&read).expect("a read answer at the cap fits one frame");
    assert_eq!(read_toolhost(&bytes).unwrap(), read);
}

#[test]
fn every_frame_round_trips_through_the_codec() {
    for frame in every_worker_frame() {
        let bytes = encode_frame(&frame).unwrap();
        assert_eq!(read_worker(&bytes).unwrap(), frame);
    }
    for frame in every_toolhost_frame() {
        let bytes = encode_frame(&frame).unwrap();
        assert_eq!(read_toolhost(&bytes).unwrap(), frame);
    }
    // The other spelling of `FileBytes`: the file does not exist.
    let absent = ToolhostFrame::FileBytes {
        id: RequestId(7),
        data_b64: None,
    };
    assert_eq!(
        read_toolhost(&encode_frame(&absent).unwrap()).unwrap(),
        absent
    );
}

/// The wire spelling a non-Rust peer implements, pinned literally.
#[test]
fn the_wire_spelling_is_pinned() {
    let exec = WorkerFrame::Exec {
        id: RequestId(7),
        session: SessionId(3),
        shell: None,
        login: false,
        script: "ls".into(),
        workdir: Some("/work/src".into()),
    };
    assert_eq!(
        serde_json::to_string(&exec).unwrap(),
        r#"{"kind":"exec","frame":{"id":7,"session":3,"shell":null,"login":false,"script":"ls","workdir":"/work/src"}}"#
    );
    let output = ToolhostFrame::Output {
        session: SessionId(3),
        stream: Stream::Stdout,
        data_b64: Chunk::new(b"hi".to_vec()).unwrap(),
    };
    assert_eq!(
        serde_json::to_string(&output).unwrap(),
        r#"{"kind":"output","frame":{"session":3,"stream":"stdout","data_b64":"aGk="}}"#
    );
    let signal = WorkerFrame::Signal {
        session: SessionId(3),
        signal: SignalKind::Terminate,
    };
    assert_eq!(
        serde_json::to_string(&signal).unwrap(),
        r#"{"kind":"signal","frame":{"session":3,"signal":"terminate"}}"#
    );
    let read = ToolhostFrame::FileBytes {
        id: RequestId(7),
        data_b64: Some(FileBody::new(b"\x89PNG".to_vec()).unwrap()),
    };
    assert_eq!(
        serde_json::to_string(&read).unwrap(),
        r#"{"kind":"file_bytes","frame":{"id":7,"data_b64":"iVBORw=="}}"#
    );
    let write = WorkerFrame::WriteFile {
        id: RequestId(7),
        path: "/work/a".into(),
        data_b64: FileBody::new(b"hi".to_vec()).unwrap(),
    };
    assert_eq!(
        serde_json::to_string(&write).unwrap(),
        r#"{"kind":"write_file","frame":{"id":7,"path":"/work/a","data_b64":"aGk="}}"#
    );
    let hello = ToolhostFrame::Hello(Hello {
        protocol: TOOLHOST_PROTOCOL_VERSION,
        source_digest: "ab".into(),
    });
    assert_eq!(
        serde_json::to_string(&hello).unwrap(),
        r#"{"kind":"hello","frame":{"protocol":2,"source_digest":"ab"}}"#
    );
}

#[test]
fn a_hello_from_another_protocol_or_source_is_a_toolhost_mismatch() {
    assert_eq!(Hello::current().check(), Ok(()));
    let other_protocol = Hello {
        protocol: TOOLHOST_PROTOCOL_VERSION + 1,
        source_digest: "0".repeat(64),
    };
    assert_eq!(
        other_protocol.check(),
        Err(ToolhostMismatch::Protocol {
            stated: TOOLHOST_PROTOCOL_VERSION + 1,
            expected: TOOLHOST_PROTOCOL_VERSION,
        })
    );
    let other_source = Hello {
        protocol: TOOLHOST_PROTOCOL_VERSION,
        source_digest: "0".repeat(64),
    };
    let refusal = other_source.check().unwrap_err();
    assert!(matches!(refusal, ToolhostMismatch::SourceDigest { .. }));
    assert!(refusal.to_string().starts_with("toolhost_mismatch: "));
}

/// The workspace root: this crate sits two levels below it.
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
}

/// The in-tree packages `kata-toolhost` compiles in, as workspace-relative
/// directories, sorted: `kata-toolhost` itself and the closure of its NORMAL
/// dependencies that `cargo metadata` resolves to a path in this workspace.
/// Read from cargo, not from `build.rs`, so a new path dependency of the
/// toolhost or of anything it links is a package this list gains on its own.
fn toolhost_in_tree_closure() -> Vec<String> {
    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata prints JSON");
    let root = workspace_root().canonicalize().unwrap();
    let packages = metadata["packages"].as_array().expect("a package list");
    let directory_of = |package: &serde_json::Value| -> PathBuf {
        Path::new(package["manifest_path"].as_str().expect("a manifest path"))
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap()
    };
    let mut pending = vec![
        packages
            .iter()
            .find(|package| package["name"] == "kata-toolhost")
            .map(directory_of)
            .expect("kata-toolhost is a workspace package"),
    ];
    let mut closure = std::collections::BTreeSet::new();
    while let Some(directory) = pending.pop() {
        if !closure.insert(directory.clone()) {
            continue;
        }
        let package = packages
            .iter()
            .find(|package| directory_of(package) == directory)
            .unwrap_or_else(|| panic!("no workspace package at {}", directory.display()));
        for dependency in package["dependencies"].as_array().unwrap() {
            let normal = dependency["kind"].is_null();
            if let (true, Some(path)) = (normal, dependency["path"].as_str()) {
                pending.push(Path::new(path).canonicalize().unwrap());
            }
        }
    }
    closure
        .into_iter()
        .map(|directory| {
            directory
                .strip_prefix(&root)
                .expect("an in-tree package sits under the workspace root")
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// **The digest's roots are exactly the in-tree source `kata-toolhost`
/// compiles in.** `build.rs`'s `ROOTS` (compiled in as
/// `KATA_TOOLHOST_SOURCE_ROOTS`) equal each package of
/// [`toolhost_in_tree_closure`] as its `Cargo.toml` and its `src/`, so the frame
/// codec this wire re-exports from `kata-provider-protocol` is covered and a
/// future path dependency of the toolhost fails here until `ROOTS` names it.
///
/// **Would red if:** `ROOTS` dropped a package the toolhost links (the codec
/// before this cell), or named one it does not.
#[test]
fn the_roots_are_the_toolhosts_in_tree_closure() {
    let closure = toolhost_in_tree_closure();
    assert!(
        closure
            .iter()
            .any(|package| package == "crates/provider-protocol"),
        "the toolhost links the frame codec's crate: {closure:?}"
    );
    let mut expected: Vec<String> = closure
        .iter()
        .flat_map(|package| [format!("{package}/Cargo.toml"), format!("{package}/src")])
        .collect();
    expected.sort();
    let mut roots: Vec<String> = env!("KATA_TOOLHOST_SOURCE_ROOTS")
        .split(',')
        .map(str::to_owned)
        .collect();
    roots.sort();
    assert_eq!(roots, expected);
}

/// The digest's input recomputed here, independently of `build.rs`, from the
/// files on disk: for every package of [`toolhost_in_tree_closure`], its
/// `Cargo.toml` and every file under its `src/`, with its bytes, sorted by its
/// workspace-relative path.
fn source_files() -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, relative: &str, out: &mut Vec<(String, PathBuf)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let relative = format!("{relative}/{name}");
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &relative, out);
            } else {
                out.push((relative, entry.path()));
            }
        }
    }
    let workspace = workspace_root();
    let mut files = Vec::new();
    for package in toolhost_in_tree_closure() {
        files.push((
            format!("{package}/Cargo.toml"),
            workspace.join(&package).join("Cargo.toml"),
        ));
        walk(
            &workspace.join(&package).join("src"),
            &format!("{package}/src"),
            &mut files,
        );
    }
    files.sort();
    files
        .into_iter()
        .map(|(relative, path)| (relative, std::fs::read(path).unwrap()))
        .collect()
}

/// `build.rs`'s encoding over `files`.
fn digest_of(files: &[(String, Vec<u8>)]) -> String {
    let mut hasher = blake3::Hasher::new();
    for (relative, contents) in files {
        hasher.update(&(relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(&(contents.len() as u64).to_le_bytes());
        hasher.update(contents);
    }
    hasher.finalize().to_hex().to_string()
}

/// One file of each package the toolhost compiles in, and each package's
/// manifest: the inputs [`a_changed_byte_of_any_covered_package_is_another_digest`]
/// flips.
const COVERED_SAMPLES: [&str; 6] = [
    "bin/kata-toolhost/Cargo.toml",
    "bin/kata-toolhost/src/main.rs",
    "crates/provider-protocol/Cargo.toml",
    "crates/provider-protocol/src/lib.rs",
    "crates/toolhost-protocol/Cargo.toml",
    "crates/toolhost-protocol/src/lib.rs",
];

/// **The compiled digest is the blake3 of the source the toolhost compiles in,
/// as it is on disk.** The recomputation covers every package of the toolhost's
/// in-tree closure, the frame codec's crate included (its file list names each
/// of [`COVERED_SAMPLES`]), and equals the constant `build.rs` compiled.
///
/// **Would red if:** `build.rs` dropped a root (a byte of that package would
/// no longer move the digest a `Hello` states), or encoded the files otherwise.
#[test]
fn the_source_digest_is_the_blake3_of_the_source_as_built() {
    let files = source_files();
    for covered in COVERED_SAMPLES {
        assert!(
            files.iter().any(|(relative, _)| relative == covered),
            "{covered} is not among the digest's inputs"
        );
    }
    assert_eq!(TOOLHOST_SOURCE_DIGEST.len(), 64);
    assert_eq!(TOOLHOST_SOURCE_DIGEST, digest_of(&files));
}

/// **One changed byte of any covered package is another digest.** The same
/// inputs with one byte of each of [`COVERED_SAMPLES`] flipped, one at a time,
/// hash to a digest other than the compiled one and other than each other, so a
/// toolhost built from a changed toolhost, wire or frame codec states a `Hello`
/// this build refuses.
///
/// **Would red if:** the recomputation, which the cell above holds equal to the
/// compiled digest, did not read one of those files.
#[test]
fn a_changed_byte_of_any_covered_package_is_another_digest() {
    let files = source_files();
    let mut seen = std::collections::BTreeSet::from([TOOLHOST_SOURCE_DIGEST.to_owned()]);
    for covered in COVERED_SAMPLES {
        let mut changed = files.clone();
        let file = changed
            .iter_mut()
            .find(|(relative, _)| relative == covered)
            .unwrap_or_else(|| panic!("{covered} is an input"));
        file.1[0] ^= 1;
        assert!(
            seen.insert(digest_of(&changed)),
            "flipping a byte of {covered} left the digest where another input put it"
        );
    }
}

/// The refused set: a dependency, in any dependency table (target-specific ones
/// included), whose name or `package` rename starts with `kata-` and is not
/// `kata-provider-protocol`.
#[test]
fn the_manifest_names_no_internal_crate_but_the_provider_protocol() {
    let manifest: toml::Table =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();
    let tables = ["dependencies", "build-dependencies", "dev-dependencies"];
    let mut sections: Vec<&toml::Table> = tables
        .iter()
        .filter_map(|name| manifest.get(*name).and_then(toml::Value::as_table))
        .collect();
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            sections.extend(
                tables
                    .iter()
                    .filter_map(|name| target.get(*name).and_then(toml::Value::as_table)),
            );
        }
    }
    let mut internal = Vec::new();
    for (name, spec) in sections.into_iter().flatten() {
        let package = spec
            .get("package")
            .and_then(toml::Value::as_str)
            .unwrap_or(name);
        for named in [name.as_str(), package] {
            if named.starts_with("kata-") && named != "kata-provider-protocol" {
                internal.push(named.to_owned());
            }
        }
    }
    internal.dedup();
    assert_eq!(internal, Vec::<String>::new());
}
