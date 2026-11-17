//! `kata-oci-hook` — the two `hooks.createContainer` entries an `Egress`
//! capsule's bundle carries ([`kata_worker::oci_bundle`]'s `hooks` render).
//!
//! # Where this process runs
//!
//! OCI `createContainer` hooks execute on the HOST's mount and user namespaces
//! but INSIDE the container's network namespace, in the create phase — after
//! the runtime has built the namespaces and before it starts the container's
//! init. Measured on pinned youki 0.7.0:
//! the hook sees the host rootfs and runs with the runtime's own capabilities,
//! while the container's init keeps `CapEff=0`. That is why the file kata
//! renders into the spec is THIS binary and not a helper of the runtime's:
//! its two jobs are the two pieces of guest-network truth only a process
//! standing in the guest's namespace can produce.
//!
//! # The two subcommands
//!
//! * `kata-oci-hook loopback-up --ip <absolute path>` — execs
//!   `<path> link set lo up` in this namespace. No crate in kata's tree speaks
//!   rtnetlink — rustix's `netdevice` surface reaches interface name↔index
//!   ioctls, not flag sets — so the pinned iproute2 binary performs the
//!   sixteen-byte flags write it exists for. `ip` is exec'd BY ABSOLUTE PATH
//!   out of the same content-addressed provider-store entry this hook resolves
//!   from: the entry is re-hashed at resolve exactly like
//!   `kata-provider-youki` itself, which is why no second pin exists for it.
//! * `kata-oci-hook hand-listener --port <P> --to <absolute host unix socket>` —
//!   binds `127.0.0.1:<P>` inside this namespace, passes the LISTENING
//!   descriptor to the worker over `SCM_RIGHTS` on the host-side socket, and
//!   waits for the worker's one-byte acknowledgement before exiting. The wait
//!   is BOUNDED ([`ACK_BUDGET`]): a worker that never answers fails this hook,
//!   which fails the create — a guest whose proxy is absent is refused rather
//!   than started. The descriptor, not a port number, is what travels: the
//!   guest's whole network namespace owns `127.0.0.1:<P>` only while this
//!   listener is open, and the worker inheriting the fd is the claim that the
//!   proxy's accept queue is the same queue the guest will connect to.
//!
//! A non-zero exit is the refusal: youki treats any failed `createContainer`
//! hook as a failed create, which the worker's drive then reports as a refused
//! stage (a `kata_worker::oci_driver::OciDriveRefusal`) — never as a stage that
//! ran without its declared egress.

use std::io::IoSlice;
use std::io::Read;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::AsFd;
use std::path::Path;
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;
use std::time::Duration;

use rustix::cmsg_space;
use rustix::net::SendAncillaryBuffer;
use rustix::net::SendAncillaryMessage;
use rustix::net::SendFlags;
use rustix::net::sendmsg;

/// The one payload byte the fd travels on. A receiver that reads the byte and
/// finds no ancillary message knows the handoff lied.
const FD_MARKER: u8 = b'F';

/// The one byte the worker sends back once the listener fd is ITS fd — the
/// handshake's second half, so a create cannot complete while the descriptor
/// still lives only in a process about to die.
const ACK_BYTE: u8 = b'A';

/// How long `hand-listener` waits for the worker's ack before failing the
/// create. Longer than the worker's own handoff gate
/// (`kata_worker::oci_driver::EGRESS_HANDOFF_BUDGET`), so the worker is the
/// clock that decides first; this bound exists for the case where the worker
/// is dead rather than slow.
const ACK_BUDGET: Duration = Duration::from_secs(45);

/// Exit code for every refusal this binary produces itself. Distinct from `1`
/// so a runtime log that reports `exit status 2` reads as "the hook refused"
/// rather than an unclassified failure.
const EXIT_REFUSED: u8 = 2;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("kata-oci-hook: {reason}");
            ExitCode::from(EXIT_REFUSED)
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [subcommand, flag, value] if subcommand == "loopback-up" && flag == "--ip" => {
            loopback_up(Path::new(value))
        }
        [subcommand, port_flag, port, to_flag, to]
            if subcommand == "hand-listener" && port_flag == "--port" && to_flag == "--to" =>
        {
            let port = port.parse::<u16>().map_err(|e| {
                format!(
                    "--port `{port}` is not a u16 ({e}); the bundle's render is the only caller"
                )
            })?;
            hand_listener(port, Path::new(to))
        }
        _ => Err(format!(
            "usage: `kata-oci-hook loopback-up --ip <absolute path>` or \
             `kata-oci-hook hand-listener --port <port> --to <absolute unix socket>` — \
             got {args:?}. A `hooks.createContainer` entry is rendered by \
             `oci_bundle::spec_for` and is the only caller; anything else is a mistake."
        )),
    }
}

/// `<ip> link set lo up` inside this network namespace.
///
/// The path must be ABSOLUTE: the render hands us the provider entry's `ip`
/// member verbatim, and a relative one would resolve against a working
/// directory neither kata nor the runtime owns.
fn loopback_up(ip: &Path) -> Result<(), String> {
    if !ip.is_absolute() {
        return Err(format!(
            "--ip `{path}` is not absolute; the provider entry's `ip` member is named by path and \
             a relative one resolves against a working directory this process does not own",
            path = ip.display(),
        ));
    }
    let status = Command::new(ip)
        .args(["link", "set", "lo", "up"])
        .env_clear()
        .stdin(Stdio::null())
        .status()
        .map_err(|e| {
            format!(
                "could not exec `{path} link set lo up`: {e}",
                path = ip.display()
            )
        })?;
    if status.success() {
        return Ok(());
    }
    Err(format!(
        "`{path} link set lo up` exited {status}. The guest's loopback is the only interface its \
         namespace has; a create that proceeds without it hands the proxy contract a namespace \
         it cannot bind in.",
        path = ip.display(),
    ))
}

/// Connect the handoff socket at `to` without handing the kernel `to` itself.
///
/// `to` lies under the worker's data directory and attempt root, so its length is
/// the operator's to choose, while `sun_path` holds 108 bytes. The address the
/// kernel sees is `/proc/self/fd/<fd>/<name>`, `<fd>` an `O_PATH` descriptor on
/// `to`'s parent held across the connect — the addressing the worker's bind
/// performs (`kata_transport::unix_socket`), spelled here because this binary
/// links `rustix` alone (see its `Cargo.toml`). The name is the worker's fixed
/// `handoff.sock`, so the short address always fits.
fn connect_through_parent(to: &Path) -> std::io::Result<UnixStream> {
    let (Some(parent), Some(name)) = (to.parent(), to.file_name()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the handoff socket path has no parent directory and file name",
        ));
    };
    let directory = rustix::fs::open(
        parent,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let address = Path::new(&format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
    UnixStream::connect(address)
}

/// Bind `127.0.0.1:{port}` in this namespace, hand the descriptor to the
/// worker over `SCM_RIGHTS`, and hold it until acknowledged.
fn hand_listener(port: u16, to: &Path) -> Result<(), String> {
    if !to.is_absolute() {
        return Err(format!(
            "--to `{path}` is not absolute; the handoff socket lives under the attempt's egress \
             directory and is named by path, not relative to a working directory",
            path = to.display(),
        ));
    }
    let listener =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).map_err(|e| {
            format!(
                "bind 127.0.0.1:{port} inside the container's network namespace: {e}. \
             A refused bind fails the create rather than starting a guest whose proxy address \
             answers to someone else."
            )
        })?;
    let mut channel = connect_through_parent(to).map_err(|e| {
        format!(
            "connect the handoff socket `{path}`: {e}. The worker binds it before the assignment \
             is accepted; an absent listener means the proxy side is gone and this create is \
             refused.",
            path = to.display(),
        )
    })?;
    // Both directions bounded: a peer that wedges mid-handoff must not hang
    // the create phase forever — the runtime would wait on this hook's exit.
    channel.set_read_timeout(Some(ACK_BUDGET)).map_err(|e| {
        format!(
            "set the ack read timeout on `{path}`: {e}",
            path = to.display()
        )
    })?;
    channel.set_write_timeout(Some(ACK_BUDGET)).map_err(|e| {
        format!(
            "set the write timeout on `{path}`: {e}",
            path = to.display()
        )
    })?;

    let mut space = [MaybeUninit::uninit(); cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let descriptors = [listener.as_fd()];
    let pushed = ancillary.push(SendAncillaryMessage::ScmRights(&descriptors));
    if !pushed {
        return Err(
            "the SCM_RIGHTS ancillary buffer refused one fd — a layout bug, not a runtime \
             condition"
                .to_owned(),
        );
    }
    sendmsg(
        &channel,
        &[IoSlice::new(&[FD_MARKER])],
        &mut ancillary,
        SendFlags::empty(),
    )
    .map_err(|e| {
        format!(
            "sendmsg the listener fd over `{path}`: {e}",
            path = to.display()
        )
    })?;

    let mut ack = [0_u8; 1];
    channel.read_exact(&mut ack).map_err(|e| {
        format!(
            "wait {ACK_BUDGET:?} for the worker's ack on `{path}`: {e}. The listener fd stays in \
             THIS process until the worker owns a copy; a create that proceeded without the ack \
             would leave the guest connecting to a queue nobody drains.",
            path = to.display(),
        )
    })?;
    if ack[0] != ACK_BYTE {
        return Err(format!(
            "the worker's ack byte {:#04x} is not {ACK_BYTE:#04x}; the handshake speaks one byte \
             and anything else means the peer is not the worker this hook was rendered for",
            ack[0],
        ));
    }
    Ok(())
}
