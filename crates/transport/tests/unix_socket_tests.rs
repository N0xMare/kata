//! `kata_transport::unix_socket`: a socket under a directory far longer than the
//! kernel's 108-byte `sun_path` binds, connects and carries bytes, and its inode
//! sits at the REAL path.
//!
//! The oracles do not share the code under test: the kernel's own refusal of the
//! real path (through `std`, directly) proves the directory is long enough to
//! matter, and `symlink_metadata` on the real path proves where the socket landed.

use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use kata_transport::unix_socket::{
    UnixSocketAddress, UnixSocketAddressError, bind_std, connect_std,
};
use kata_types::unix_socket_name::{MAX_SOCKET_NAME_BYTES, SocketNameRefusal};

/// A directory under `root` whose own path is at least 300 bytes.
fn long_directory(root: &Path) -> PathBuf {
    let mut dir = root.to_path_buf();
    while dir.as_os_str().len() < 300 {
        dir.push("d".repeat(60));
    }
    std::fs::create_dir_all(&dir).expect("the long directory");
    dir
}

/// The kernel refuses `path` when handed it directly — the cell's premise.
fn assert_the_kernel_refuses_the_real_path(path: &Path) {
    let direct = std::os::unix::net::UnixListener::bind(path);
    assert!(
        direct.is_err(),
        "a {}-byte path must not be bindable directly, or this cell proves nothing",
        path.as_os_str().len()
    );
    assert!(
        !path.exists(),
        "the refused direct bind left nothing behind"
    );
}

#[test]
fn a_socket_under_a_300_byte_directory_binds_connects_and_carries_bytes() {
    let root = tempfile::tempdir().expect("a temp root");
    let path = long_directory(root.path()).join("handoff.sock");
    assert_the_kernel_refuses_the_real_path(&path);

    let listener = bind_std(&path).expect("binds through the parent's descriptor");
    let metadata = std::fs::symlink_metadata(&path).expect("the socket inode is at the real path");
    assert!(metadata.file_type().is_socket(), "{metadata:?}");

    let mut client = connect_std(&path).expect("connects through the parent's descriptor");
    let (mut server, _) = listener.accept().expect("accepts");
    client.write_all(b"ping").expect("writes");
    let mut got = [0_u8; 4];
    server.read_exact(&mut got).expect("reads");
    assert_eq!(&got, b"ping");
}

#[tokio::test]
async fn the_tokio_pair_round_trips_under_the_same_directory() {
    let root = tempfile::tempdir().expect("a temp root");
    let path = long_directory(root.path()).join("worker.sock");
    assert_the_kernel_refuses_the_real_path(&path);

    let listener = kata_transport::unix_socket::bind_tokio(&path).expect("binds");
    let connect = tokio::spawn({
        let path = path.clone();
        async move { kata_transport::unix_socket::connect_tokio(&path).await }
    });
    let (mut server, _) = listener.accept().await.expect("accepts");
    let mut client = connect.await.expect("joins").expect("connects");
    tokio::io::AsyncWriteExt::write_all(&mut client, b"pong")
        .await
        .expect("writes");
    let mut got = [0_u8; 4];
    tokio::io::AsyncReadExt::read_exact(&mut server, &mut got)
        .await
        .expect("reads");
    assert_eq!(&got, b"pong");
}

/// The production transport at the same depth: `listen` + `connect` succeed and
/// the listener's own drop unlinks the REAL path.
#[tokio::test]
async fn the_local_socket_transport_listens_and_connects_under_a_long_data_dir() {
    let root = tempfile::tempdir().expect("a temp root");
    let path = long_directory(root.path()).join("worker.sock");
    assert_the_kernel_refuses_the_real_path(&path);

    let listener = kata_transport::LocalSocketTransport::listen(&path).expect("listens");
    assert!(
        std::fs::symlink_metadata(&path)
            .expect("bound at the real path")
            .file_type()
            .is_socket()
    );
    let accept = tokio::spawn(async move {
        let accepted = listener.accept_next().await;
        (listener, accepted)
    });
    let worker = kata_transport::LocalSocketTransport::connect(&path)
        .await
        .expect("connects");
    let (listener, accepted) = accept.await.expect("joins");
    accepted.expect("accepts");
    drop(worker);
    drop(listener);
    assert!(
        std::fs::symlink_metadata(&path).is_err(),
        "the listener's drop removed the socket at its real path"
    );
}

/// The one bound left, both ways: a name of exactly the bound binds under the long
/// directory; one byte more is refused naming the limit, and nothing is created.
#[test]
fn the_name_bound_admits_its_edge_and_refuses_one_byte_past_it() {
    let root = tempfile::tempdir().expect("a temp root");
    let dir = long_directory(root.path());

    let at = dir.join("n".repeat(MAX_SOCKET_NAME_BYTES));
    let _listener = bind_std(&at).expect("an 82-byte name binds under a 300-byte directory");
    connect_std(&at).expect("and connects");

    let over = dir.join("n".repeat(MAX_SOCKET_NAME_BYTES + 1));
    let refusal = UnixSocketAddress::resolve(&over).expect_err("an 83-byte name is refused");
    assert!(
        matches!(
            refusal,
            UnixSocketAddressError::Name(SocketNameRefusal::NameTooLong { len: 83, .. })
        ),
        "{refusal}"
    );
    assert!(
        refusal.to_string().contains("at most 82 bytes"),
        "{refusal}"
    );
    assert!(!over.exists(), "the refusal created nothing");
}

/// A parent that does not exist is refused naming it — the address is never built
/// against a descriptor that names something else.
#[test]
fn an_absent_parent_is_refused_naming_it() {
    let root = tempfile::tempdir().expect("a temp root");
    let missing = root.path().join("absent");
    let refusal = UnixSocketAddress::resolve(&missing.join("x.sock"))
        .expect_err("an absent parent is refused");
    assert!(
        matches!(&refusal, UnixSocketAddressError::Parent { parent, .. } if *parent == missing),
        "{refusal}"
    );
}
