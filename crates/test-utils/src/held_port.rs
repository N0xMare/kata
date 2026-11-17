//! A loopback port held out of the kernel's ephemeral pool for as long as a
//! test needs it, while the code under test binds it by number.
//!
//! The pattern this replaces — bind `127.0.0.1:0`, read the port, drop the
//! listener, hand the number to the code under test — returns the port to the
//! pool between the drop and the code's own bind, and any process's next `:0`
//! bind may be handed it. A [`HeldPort`] keeps a socket bound to the port with
//! `SO_REUSEADDR` set and never listens on it. Measured on Linux (kernel 7.0,
//! the host netns):
//!
//! * no `:0` bind is handed a port while it is held — before the code under
//!   test binds it, while it listens, and after it closes (0 of 20 000 binds
//!   landed on 2 000 held ports; 5 684 of 20 000 did once the same ports were
//!   released);
//! * an explicit bind of the port by a `SO_REUSEADDR` socket — what
//!   `std::net::TcpListener::bind` creates on Unix — succeeds while the port is
//!   held and nothing listens on it, and is refused `EADDRINUSE` while another
//!   socket listens on it.
//!
//! So the code under test can bind the port, and a test can still prove a
//! listener released it by binding it again. What a hold does NOT refuse: an
//! explicit bind of the number by some other process that already knows it.

use std::net::SocketAddr;

/// One held loopback port. Dropping it returns the port to the pool, so keep
/// it for as long as anything is meant to bind or answer on the port.
#[derive(Debug)]
pub struct HeldPort {
    addr: SocketAddr,
    _socket: tokio::net::TcpSocket,
}

impl HeldPort {
    /// Hold a fresh loopback port the kernel picks.
    ///
    /// # Errors
    /// The socket, its `SO_REUSEADDR` option, its bind or its address read failed.
    pub fn new() -> std::io::Result<Self> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        socket.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let addr = socket.local_addr()?;
        Ok(Self {
            addr,
            _socket: socket,
        })
    }

    /// The held address, `127.0.0.1:<port>`.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::io::ErrorKind;
    use std::net::TcpListener;

    use super::HeldPort;

    /// **No `:0` bind is handed a held port, and the code under test can still
    /// bind it.** The kernel's own allocation is the witness: 200 held ports, and
    /// 1 000 `std` listeners on `:0` beside them — before the code binds, while
    /// it listens, and after it closes — none of which lands on a held port.
    /// The control releases the same ports and asks again; ports landing on them
    /// then proves the asking can reach them at all.
    ///
    /// **Would red if:** the hold released the port (watched: `held, unbound: 24
    /// of 1000 :0 binds landed on a held port`), or set no `SO_REUSEADDR`
    /// (watched: `the code binds 127.0.0.1:<port>: Address already in use`).
    #[test]
    fn no_ephemeral_bind_is_handed_a_held_port_and_the_code_can_bind_it() {
        let held: Vec<HeldPort> = (0..200).map(|_| HeldPort::new().unwrap()).collect();
        let ports: HashSet<u16> = held.iter().map(|hold| hold.addr().port()).collect();
        let landed = |label: &str| -> usize {
            let listeners: Vec<TcpListener> = (0..1_000)
                .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
                .collect();
            let landed = listeners
                .iter()
                .filter(|listener| ports.contains(&listener.local_addr().unwrap().port()))
                .count();
            eprintln!("{label}: {landed} of 1000 :0 binds landed on a held port");
            landed
        };
        assert_eq!(landed("held, unbound"), 0);

        let bound: Vec<TcpListener> = held
            .iter()
            .map(|hold| {
                TcpListener::bind(hold.addr())
                    .unwrap_or_else(|error| panic!("the code binds {}: {error}", hold.addr()))
            })
            .collect();
        assert_eq!(landed("held, listened on"), 0);
        assert_eq!(
            TcpListener::bind(held[0].addr())
                .map(drop)
                .map_err(|e| e.kind()),
            Err(ErrorKind::AddrInUse),
            "a second listener is refused while the code listens"
        );

        drop(bound);
        assert_eq!(landed("held, released by the code"), 0);
        drop(
            TcpListener::bind(held[0].addr())
                .expect("a released held port binds again, as a release check does"),
        );

        drop(held);
        let mut control = 0;
        for _ in 0..10 {
            control += landed("control: the same ports released");
            if control > 0 {
                break;
            }
        }
        assert!(control > 0, "the control never reached a released port");
    }
}
