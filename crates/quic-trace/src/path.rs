use std::net::{IpAddr, SocketAddr};

use crate::Handle;
use crate::backend::{Event, Tracepoint};

/// The local and peer addresses a connection sends between.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionPath {
    pub(crate) local: SocketAddr,
    pub(crate) peer: SocketAddr,
}

impl ConnectionPath {
    /// Describe a path from the local address a connection sends from to its peer.
    ///
    /// The local address may be the wildcard address when the socket is bound
    /// to it and the stack does not learn the address the kernel chose.
    pub fn new(local: SocketAddr, peer: SocketAddr) -> Self {
        Self { local, peer }
    }
}

/// Encode an address as IPv6, with IPv4 written as IPv4-mapped IPv6.
///
/// The provider carries the 128 address bits as two halves in network byte
/// order, so the encoding is the value `Ipv6Addr::to_bits` returns.
#[cfg_attr(not(all(feature = "lttng", target_os = "linux")), allow(dead_code))]
pub(crate) fn address_bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => address.to_ipv6_mapped().to_bits(),
        IpAddr::V6(address) => address.to_bits(),
    }
}

impl Handle {
    /// Record the path a connection sends on.
    ///
    /// A stack records the path when it creates a connection and again whenever
    /// the path changes, such as after a validated migration. Each event holds
    /// until the connection's next one, which lets analysis join the
    /// connection's packets to a packet capture by address.
    pub fn connection_path(&self, connection_id: u64, path: ConnectionPath) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        if !inner.enabled(Tracepoint::ConnectionPath) {
            return;
        }
        inner.emit(Event::ConnectionPath {
            timestamp_ns: inner.now_ns(),
            connection_id,
            path,
        });
    }
}
